import os
import sys
import time
import json
from pathlib import Path
from collections import deque
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit
import ctypes
from ctypes import wintypes

BASE_DIR = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent

STATUS_COLORS = {"ONLINE": "#34d399", "OFFLINE": "#f87171"}


class FILETIME(ctypes.Structure):
    """Windows API FILETIME structure for process timestamp calculation."""
    _fields_ = [("dwLow", wintypes.DWORD), ("dwHigh", wintypes.DWORD)]


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    """Windows API structure for process memory counters."""
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


class MEMORYSTATUSEX(ctypes.Structure):
    """Windows API structure for system memory load metrics."""
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]

# =============================================================================
# PYSIDE6 / QT WIDGETS AND CORE ENGINE CLASSES
# =============================================================================
from PySide6.QtWidgets import (
    QApplication, QWidget, QPushButton, QCompleter,
    QTableWidgetItem, QMessageBox, QHeaderView,
    QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QSpinBox, QFrame, QLineEdit
)
from PySide6.QtCore import QFile, QThread, Signal, QStringListModel, Qt, QTimer
from PySide6.QtGui import QTextCursor, QColor
from PySide6.QtUiTools import QUiLoader

# Project internal modules
import storageH
import monitor
from settings_manager import SettingsManager
from scheduler import ServerScheduler

# =============================================================================
# CLASS: BatchCheckWorker (Background Thread for Concurrent Testing)
# =============================================================================

class BatchCheckWorker(QThread):
    """Background worker thread running batch network verifications concurrently."""

    # Signal emitted the instant an individual target check finishes
    target_checked = Signal(dict)

    # Signal emitted when every queued target in the batch has completed
    batch_finished = Signal()

    def __init__(self, targets: list, selected_mode: str, max_workers: int = 2, timeout: float = 3.0):
        """
        Initializes the batch worker thread.
        
        Parameters:
        - targets: The list of server target dictionaries to verify.
        - selected_mode: Protocol selected ('TCP' or 'PING').
        - max_workers: Maximum number of simultaneous worker threads (governed by Settings).
        - timeout: Socket connection or ICMP ping timeout in seconds.
        """
        super().__init__()
        self.targets = targets
        self.selected_mode = selected_mode
        self.max_workers = max_workers
        self.timeout = timeout

    def _execute_single(self, target: dict) -> tuple:
        """
        Worker task invoked inside the thread pool for one individual target.
        Extracts host parameters, calls monitor.py routines, and returns the ID and payload.
        """
        equipment = target.get("name", "Unknown")
        host = target.get("host", "")
        port = target.get("port", 80) or 80

        # Execute check based on the active protocol chosen in the header (or per-target if SELECTED)
        proto = target.get("check_type", "TCP").upper() if self.selected_mode == "SELECTED" else self.selected_mode
        if proto == "TCP":
            result = monitor.TCP_check(
                equipment=equipment,
                host=host,
                port=int(port),
                timeout=self.timeout
            )
        else:
            result = monitor.ping_check(
                equipment=equipment,
                host=host,
                timeout=self.timeout
            )

        # Return target ID alongside raw test result
        return target.get("id"), result

    def run(self):
        """
        Main execution loop for the background thread.
        Uses ThreadPoolExecutor to bound active connections to max_workers.
        """
        check_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Bounded worker pool: restricts active simultaneous threads to user settings
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            
            # Map each submitted task future to the target's unique ID
            future_to_id = {
                executor.submit(self._execute_single, target): target.get("id")
                for target in self.targets
            }

            # As each individual worker finishes its check, yield the result immediately
            for future in as_completed(future_to_id):
                target_id = future_to_id[future]
                try:
                    tid, result = future.result()

                    # Emit the completed result payload to the main thread via Qt Signal
                    self.target_checked.emit({
                        "target_id": tid,
                        "result": result,
                        "timestamp": check_time
                    })

                except Exception as e:
                    # Guard against unhandled networking exceptions crashing the thread
                    target_obj = next((t for t in self.targets if t.get("id") == target_id), {})
                    fallback_proto = target_obj.get("check_type", "TCP").upper() if self.selected_mode == "SELECTED" else self.selected_mode
                    self.target_checked.emit({
                        "target_id": target_id,
                        "result": {
                            "status": "OFFLINE",
                            "resolved_ip": None,
                            "response_time_ms": None,
                            "check_type": fallback_proto,
                            "error": f"Worker execution failure: {e}"
                        },
                        "timestamp": check_time
                    })

        # Notify the UI that the entire verification run is complete
        self.batch_finished.emit()


# =============================================================================
# CLASS: SingleTargetWorker (Inspector Button Background Thread)
# =============================================================================

class SingleTargetWorker(QThread):
    """Background worker thread that runs an individual target network verification."""

    check_finished = Signal(dict)

    def __init__(self, target: dict, mode: str, timeout: float = 3.0):
        """Initializes target parameters and network mode for background check."""
        super().__init__()
        self.equipment = target.get("name", "Unknown")
        self.host      = target.get("host", "")
        self.port      = int(target.get("port", 80) or 80)
        self.mode      = mode        # "PING", "TCP", or "BOTH"
        self.timeout   = timeout

    def run(self):
        """
        Entry point called automatically when QThread.start() is invoked.
        Runs the appropriate check(s) and emits check_finished when done.
        """
        # Initialise result placeholders -- only the relevant ones will be filled.
        ping_res = None
        tcp_res  = None

        if self.mode in ("PING", "BOTH"):
            ping_res = monitor.ping_check(
                equipment=self.equipment, host=self.host, timeout=self.timeout
            )
        if self.mode in ("TCP", "BOTH"):
            tcp_res = monitor.TCP_check(
                equipment=self.equipment, host=self.host, port=self.port, timeout=self.timeout
            )

        # Package both results and the mode into one dict for the receiver
        self.check_finished.emit({
            "mode":     self.mode,
            "ping_res": ping_res,
            "tcp_res":  tcp_res,
        })


# =============================================================================
# MAIN CONTROLLER CLASS: NetworkMonitorUI
# =============================================================================

class NetworkMonitorUI:
    """
    Central controller class coordinating UI state, server tables,
    CRUD operations, dual-protocol inspection, settings, and background verification.
    """

    def __init__(self, ui_file_path: str = "gui.ui"):
        """Loads user interface from UI file and initializes application state."""
        loader = QUiLoader()
        ui_file = QFile(ui_file_path)
        if not ui_file.open(QFile.ReadOnly):
            raise FileNotFoundError(f"Could not open {ui_file_path}")

        self.window = loader.load(ui_file)
        ui_file.close()

        # Connect window close event to clean shutdown handler
        self.window.closeEvent = self._handle_window_close

        # Application State
        self.targets = []
        self.target_lookup = {}
        self.row_by_id = {}             # Maps target_id -> row integer index in tblAllServers
        self.recent_targets = []        # Stores the last 6 checked endpoints for Dashboard
        self.current_inspected_id = None
        self.editing_target_id = None
        self.remaining_queue = 0
        self.worker = None          # Holds the active BatchCheckWorker thread (or None)
        self.single_worker = None   # Holds the active SingleTargetWorker thread (or None)
        
        # =====================================================================
        # INDEPENDENT SERVER SCHEDULER
        # =====================================================================
        # Each server gets its own QTimer with independent cadences (60s when ONLINE,
        # 30s when OFFLINE). When any server's timer fires, it emits `check_requested`,
        # which triggers `_on_scheduled_check` on the main GUI thread.
        self.scheduler = ServerScheduler()
        self.scheduler.check_requested.connect(self._on_scheduled_check)
        self.scheduled_workers = []  # Retains active worker thread references to prevent GC
        
        # =====================================================================
        # MODULAR CONFIGURATION & SETTINGS ENGINE
        # =====================================================================
        # Instead of hardcoding defaults in memory, we instantiate our generic
        # SettingsManager. On boot, it automatically loads config/settings.json
        # from disk (or creates it with defaults if running for the first time).
        # Any preferences the user saved previously are immediately restored!
        self.settings = SettingsManager(filepath="config/settings.json")

        # Read saved user preferences (with fallback to safe defaults)
        self.max_workers = int(self.settings.get("max_workers", 24))
        self.check_timeout = float(self.settings.get("check_timeout", 3.0))
        self.online_interval = int(self.settings.get("online_interval", 60))
        self.offline_interval = int(self.settings.get("offline_interval", 30))
        self.monitor_refresh_ms = int(self.settings.get("monitor_refresh_ms", 2000))

        # Pass configured intervals to ServerScheduler
        self.scheduler.set_intervals(self.online_interval, self.offline_interval)

        # Optimization: Debounced disk save timer
        # Prevents writing targets.json 100 times in rapid succession
        self.save_timer = QTimer()
        self.save_timer.setSingleShot(True)
        self.save_timer.setInterval(1500)  # Flush to disk at most once every 1.5 seconds
        self.save_timer.timeout.connect(self.flush_targets_to_disk)
        self.is_dirty = False

        # Configure visual components, bind signals, and initialize settings
        self.configure_tables()
        self.load_target_data()
        self.setup_navigation()
        self.setup_actions()
        self.setup_search_autocomplete()
        self.setup_table_filters()
        self.setup_settings_page()
        self.refresh_logs()

        # Server Inspector split layout
        self.window.detBottomRow.setStretch(0, 1)
        self.window.detBottomRow.setStretch(1, 1)

        # =====================================================================
        # APP RESOURCE & STORAGE MONITORING STATE (PERSISTED)
        # =====================================================================
        # File where cumulative metrics survive app restarts
        self.metrics_filepath = str(BASE_DIR / "config" / "log_metrics.json")
        self.log_filepath = str(BASE_DIR / "storage" / "monitor.log")
        self.scheduled_history = deque()  # (timestamp, bytes_added) over the last 5 minutes (300s)
        self.last_known_log_size = os.path.getsize(self.log_filepath) if os.path.exists(self.log_filepath) else 0

        # CPU measurement baseline using Windows native GetProcessTimes via ctypes
        self._prev_kernel_time = 0
        self._prev_user_time = 0
        self._prev_perf_time = time.perf_counter()
        self._init_cpu_baseline()

        # Load persisted metrics from disk (or initialize with zero)
        self.storage_metrics = self._load_storage_metrics()

        # Telemetry UI update timer (governed by user settings: 500ms, 1000ms, 2000ms, 5000ms)
        self.telemetry_timer = QTimer()
        self.telemetry_timer.setInterval(self.monitor_refresh_ms)
        self.telemetry_timer.timeout.connect(self.update_resource_telemetry_ui)
        self.telemetry_timer.start()

        # Initialize Default Target for Inspector and Dashboard Quick View
        if self.targets:
            first_id = self.targets[0].get("id")
            self.current_inspected_id = first_id
            self.populate_server_detail_page(first_id)
            self.update_dashboard_quick_target_card(first_id)


    def _on_scheduled_check(self, target: dict):
        """Handles periodic timer triggers for individual scheduled server checks."""
        if not target:
            return
        mode = target.get("check_type", "TCP").upper()
        worker = SingleTargetWorker(target=target, mode=mode, timeout=self.check_timeout)
        def on_done(payload, t=target, w=worker):
            """Processes finished scheduled check and releases worker reference."""
            self._handle_single_check_finished(payload, t, source="SCHEDULED")
            if w in self.scheduled_workers:
                self.scheduled_workers.remove(w)
        worker.check_finished.connect(on_done)
        self.scheduled_workers.append(worker)
        worker.start()

    # =========================================================================
    # TABLE CONFIGURATION & DATA BINDING
    # =========================================================================

    def configure_tables(self):
        """Configures header behavior and user interaction for both tables."""
        
        # Configure All Servers Table headers
        header = self.window.tblAllServers.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents) # Name column
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents) # Host column

        # Configure Recent Servers Table headers on Dashboard
        recent_header = self.window.tblRecentServers.horizontalHeader()
        recent_header.setSectionResizeMode(QHeaderView.Stretch)

        # Connect double-click on rows to open the Server Inspector directly
        self.window.tblAllServers.cellDoubleClicked.connect(
            lambda r, _: self._open_row_inspector(self.window.tblAllServers, r)
        )
        self.window.tblRecentServers.cellDoubleClicked.connect(
            lambda r, _: self._open_row_inspector(self.window.tblRecentServers, r)
        )

    def load_target_data(self):
        """Loads data from storageH, rebuilds memory lookup indexes, and updates views."""
        self.targets = storageH.load_targets()
        self.target_lookup = {t["id"]: t for t in self.targets if "id" in t}

        # Populate the recent targets cache with previously checked items
        checked = [t for t in self.targets if t.get("last_checked")]
        checked.sort(key=lambda x: x.get("last_checked", ""), reverse=True)
        self.recent_targets = checked[:22] if checked else self.targets[:22]

        # Initial render of visual components
        self.populate_all_servers_table()
        self.populate_recent_servers_table()
        self.update_dashboard_stat_cards()
        self.update_quick_target_combobox()

        # Start independent timers for all loaded servers, staggered by 150ms each
        for idx, target in enumerate(self.targets):
            self.scheduler.start_server_scheduler(target, delay_ms=idx * 150)

    def populate_all_servers_table(self):
        """
        Initial one-time construction of tblAllServers rows.
        Builds self.row_by_id mapping so future checks update in-place without rebuilding.
        """
        table = self.window.tblAllServers
        table.setRowCount(len(self.targets))
        self.row_by_id.clear()

        for row, target in enumerate(self.targets):
            tid = target.get("id")
            self.row_by_id[tid] = row

            # Column 0: Name (Attach target ID in UserRole)
            name_item = QTableWidgetItem(target.get("name", "Unnamed"))
            name_item.setData(Qt.UserRole, tid)
            table.setItem(row, 0, name_item)

            # Column 1: Host Address
            table.setItem(row, 1, QTableWidgetItem(str(target.get("host", ""))))

            # Column 2: Resolved IPv4
            resolved = target.get("resolved_ip") or "-"
            table.setItem(row, 2, QTableWidgetItem(str(resolved)))

            # Column 3: Type (TCP/PING)
            table.setItem(row, 3, QTableWidgetItem(str(target.get("check_type", "TCP"))))

            # Column 4: Port
            port_val = str(target.get("port")) if target.get("port") is not None else "N/A"
            table.setItem(row, 4, QTableWidgetItem(port_val))

            # Column 5: Status with color coding
            status = target.get("status", "PENDING")
            status_item = QTableWidgetItem(status)
            self._apply_status_color(status_item, status)
            table.setItem(row, 5, status_item)

            # Column 6: Response Time
            lat = target.get("response_time_ms")
            table.setItem(row, 6, QTableWidgetItem(f"{lat} ms" if lat is not None else "--"))

            # Column 7: Date & Time of last check
            table.setItem(row, 7, QTableWidgetItem(str(target.get("last_checked") or "Never")))

            # Column 8: Number of successes
            table.setItem(row, 8, QTableWidgetItem(str(target.get("successes", 0))))

            # Column 9: Number of failures
            table.setItem(row, 9, QTableWidgetItem(str(target.get("failures", 0))))

        self.window.lblTotalCountSummary.setText(f"Showing {len(self.targets)} registered servers")

    def _apply_status_color(self, item: QTableWidgetItem, status: str):
        """Helper to assign clean theme colors to status items."""
        item.setForeground(QColor(STATUS_COLORS.get(status, "#94a3b8")))

    def update_single_server_row_in_place(self, target: dict):
        """
        HIGH-PERFORMANCE OPTIMIZATION:
        Updates only the specific cells of a single row in tblAllServers.
        Avoids wiping and recreating 1,000 table items on every finished check.
        """
        tid = target.get("id")
        row = self.row_by_id.get(tid)
        if row is None:
            return

        table = self.window.tblAllServers

        # Column 2: Resolved IPv4
        resolved = target.get("resolved_ip") or "-"
        table.item(row, 2).setText(str(resolved))

        # Column 5: Status
        status = target.get("status", "PENDING")
        status_item = table.item(row, 5)
        status_item.setText(status)
        self._apply_status_color(status_item, status)

        # Column 6: Response Time
        lat = target.get("response_time_ms")
        table.item(row, 6).setText(f"{lat} ms" if lat is not None else "--")

        # Column 7: Last Checked
        table.item(row, 7).setText(str(target.get("last_checked") or "Never"))

        # Column 8: Successes
        table.item(row, 8).setText(str(target.get("successes", 0)))

        # Column 9: Failures
        table.item(row, 9).setText(str(target.get("failures", 0)))

    def populate_recent_servers_table(self):
        """Populates the bottom-left table on Dashboard with the latest checked items."""
        table = self.window.tblRecentServers
        display_targets = self.recent_targets[:22]
        table.setRowCount(len(display_targets))

        for row, target in enumerate(display_targets):
            # Column 0: Host / Device Name
            item_name = QTableWidgetItem(f"{target.get('name')} ({target.get('host')})")
            item_name.setData(Qt.UserRole, target.get("id"))
            table.setItem(row, 0, item_name)

            # Column 1: Type
            table.setItem(row, 1, QTableWidgetItem(target.get("check_type", "TCP")))

            # Column 2: Status
            status = target.get("status", "PENDING")
            status_item = QTableWidgetItem(status)
            self._apply_status_color(status_item, status)
            table.setItem(row, 2, status_item)

            # Column 3: Response Time
            lat = target.get("response_time_ms")
            table.setItem(row, 3, QTableWidgetItem(f"{lat} ms" if lat is not None else "--"))

            # Column 4: Last Checked
            table.setItem(row, 4, QTableWidgetItem(str(target.get("last_checked") or "Never")))

    def update_dashboard_stat_cards(self):
        """Calculates and refreshes all top-level stat card metrics across the dashboard."""
        total = len(self.targets)
        online_count = sum(1 for t in self.targets if t.get("status") == "ONLINE")
        offline_count = sum(1 for t in self.targets if t.get("status") == "OFFLINE")

        # Calculate average response latency across active servers
        valid_latencies = [t["response_time_ms"] for t in self.targets if t.get("response_time_ms") is not None]
        avg_lat = round(sum(valid_latencies) / len(valid_latencies), 1) if valid_latencies else 0

        # Assign values to Dashboard labels
        self.window.lblValTotal.setText(str(total))
        self.window.lblValOnline.setText(str(online_count))
        self.window.lblValOffline.setText(str(offline_count))
        self.window.lblValLatency.setText(f"{avg_lat} ms" if avg_lat > 0 else "-- ms")

    def update_quick_target_combobox(self):
        """
        Refreshes the target dropdown on the Dashboard Quick Inspector panel.
        
        Educational Context & Ponytail Principles:
        - When a server is added, updated, or removed, this method synchronizes the
          combobox items with the latest `self.targets` list.
        - Notice the use of `prev_id`: by remembering which server ID was selected
          before calling `cmb.clear()`, we restore the user's selection after reloading.
          This prevents the annoying UI bug where saving an edit or receiving a background
          poll resets the dropdown back to the first host!
        - `cmb.blockSignals(True)` prevents Qt from firing `currentIndexChanged` during
          the batch addition loop, which would cause wasted card recalculations.
        """
        cmb = self.window.cmbQuickTarget
        prev_id = cmb.currentData()
        cmb.blockSignals(True)
        cmb.clear()

        selected_idx = -1
        for idx, t in enumerate(self.targets):
            port_label = f":{t.get('port')}" if t.get("port") else ""
            cmb.addItem(f"{t.get('name')} ({t.get('host')}{port_label}) - {t.get('check_type')}", t.get("id"))
            if prev_id and t.get("id") == prev_id:
                selected_idx = idx

        if selected_idx >= 0:
            cmb.setCurrentIndex(selected_idx)
        elif self.targets:
            cmb.setCurrentIndex(0)

        cmb.blockSignals(False)

        current_id = cmb.currentData()
        if current_id:
            self.update_dashboard_quick_target_card(current_id)


    # =========================================================================
    # OPTIMIZED STORAGE SYNC & DISK DEBOUNCING
    # =========================================================================

    def schedule_disk_save(self):
        """
        Marks state as dirty and starts/resets the 1.5s flush timer.
        Ensures the application saves progress without thrashing disk I/O on every check.
        """
        self.is_dirty = True
        if not self.save_timer.isActive():
            self.save_timer.start()

    def flush_targets_to_disk(self):
        """Writes current targets state to disk once the timer expires."""
        if self.is_dirty:
            storageH.save_targets(self.targets)
            self.is_dirty = False


    # =========================================================================
    # CRUD OPERATIONS (CREATE, READ, UPDATE, DELETE)
    # =========================================================================

    # =========================================================================
    # CRUD OPERATIONS (CREATE, READ, UPDATE, DELETE) - SERVER CONFIGURATION FORM
    # =========================================================================

    def open_add_server_form(self):
        """
        Opens the embedded configuration form (page index 5) primed for a new server.
        
        -------------------------------------------------------------------------
        HOW THIS METHOD WORKS:
        -------------------------------------------------------------------------
        1. Resets self.editing_target_id to None so save_server_form knows we are
           inserting a brand-new server rather than overwriting an existing one.
        2. Clears previous input text fields to provide a clean slate.
        3. Sets default values: TCP verification mode on standard port 80.
        4. Gives initial keyboard focus to the Equipment Name input box so the user
           can immediately start typing without clicking.
        5. Switches the QStackedWidget to page 5 (pageServerForm).
        """
        # Clear the edit pointer to signal "CREATE" mode
        self.editing_target_id = None

        # Set human-friendly headers for creating a new server
        self.window.lblFormTitle.setText("Add New Monitored Server")
        self.window.lblFormSubtitle.setText(
            "Configure host domain/IP, scheduled verification method, and listening port."
        )

        # Clear previous text from input fields
        self.window.txtFormName.clear()
        self.window.txtFormHost.clear()

        # Set sensible defaults: TCP protocol on default HTTP port 80
        self.window.cmbFormType.setCurrentText("TCP")
        self.window.spnFormPort.setValue(80)
        self.handle_form_type_change("TCP")

        # Switch stacked widget to Form page (Index 5)
        self.window.stackedWidget.setCurrentIndex(5)

        # Automatically place keyboard cursor into the first input field
        self.window.txtFormName.setFocus()

    def open_edit_server_form(self):
        """
        Opens the embedded configuration form pre-filled with the selected server's data.
        
        -------------------------------------------------------------------------
        HOW THIS METHOD WORKS:
        -------------------------------------------------------------------------
        1. Checks which row is currently selected in tblAllServers. If no row is
            selected, shows an informational dialog prompting the user to select one.
        2. Retrieves the target dictionary from self.target_lookup by its unique ID.
        3. Sets self.editing_target_id to track which record is being modified.
        4. Pre-fills all form fields (Name, Host, Protocol, Port) with the existing
            values so the user only needs to change what they want to update.
        5. Switches the QStackedWidget to page 5 (pageServerForm).
        """
        selected_id = self.get_selected_server_id()
        if not selected_id:
            QMessageBox.information(
                self.window, "Selection Required",
                "Please select a server row from the table first to modify its configuration."
            )
            return

        target = self.target_lookup.get(selected_id)
        if not target:
            return

        # Store the ID being edited to signal "UPDATE" mode
        self.editing_target_id = selected_id

        # Update card titles to clearly display which equipment is being edited
        self.window.lblFormTitle.setText(f"Edit Target: {target.get('name')}")
        self.window.lblFormSubtitle.setText(f"Modifying parameters for server ID: {selected_id}")

        # Pre-fill input fields with existing data
        self.window.txtFormName.setText(target.get("name", ""))
        self.window.txtFormHost.setText(target.get("host", ""))

        check_type = target.get("check_type", "TCP").upper()
        self.window.cmbFormType.setCurrentText(check_type)
        self.window.spnFormPort.setValue(int(target.get("port") or 80))
        self.handle_form_type_change(check_type)

        # Switch to Form page (Index 5)
        self.window.stackedWidget.setCurrentIndex(5)
        self.window.txtFormName.setFocus()

    def handle_form_type_change(self, selected_type: str):
        """
        Dynamically adjusts form controls when the user toggles between TCP and PING.
        
        Why this exists:
        - In TCP mode, a port number (1-65535) is essential for opening a socket connection.
        - In PING mode (ICMP echo), ports do not exist at the protocol level (Layer 3/Network).
          We disable the port input to make this distinction visually obvious to the user.
        """
        is_tcp = (selected_type.strip().upper() == "TCP")
        self.window.spnFormPort.setEnabled(is_tcp)

        if is_tcp:
            self.window.lblFormPortHint.setText(
                "Note: TCP checks test a specific port. For web servers use 80 (HTTP) or 443 (HTTPS)."
            )
        else:
            self.window.lblFormPortHint.setText(
                "Note: For PING verification, port values are automatically omitted."
            )

    def save_server_form(self):
        """
        Validates form inputs, sanitizes host strings, persists additions or updates,
        and refreshes all connected UI views.
        
        -------------------------------------------------------------------------
        STEP-BY-STEP WORKFLOW:
        -------------------------------------------------------------------------
        1. INPUT SANITIZATION:
           Users often paste web URLs like 'https://google.com/path' or '192.168.1.1:8080'.
           Raw URLs cause socket.gethostbyname() and ping commands to fail with DNS errors.
           We automatically strip URL schemes ('http://', 'https://'), URL paths, and
           extract any embedded port numbers.
           
        2. VALIDATION:
           Ensures that both equipment name and host are not empty.
           
        3. SCHEMA COMPLETENESS:
           Ensures that whether adding or editing, every single expected key exists:
           - Global metrics (status, response_time_ms, successes, failures, etc.)
           - Dual-protocol inspection keys (tcp_status, icmp_status, latency_delta_ms, etc.)
           
        4. CACHE INVALIDATION:
           If a server's host address is edited to point to a new location, old cached
           DNS resolution, statuses, and response times are reset to PENDING so stale
           telemetry from the old server is not displayed.
           
        5. PERSISTENCE & VIEW SYNC:
           Saves immediately to config/targets.json, reloads data tables and search
           autocompletion, and returns the user back to the All Devices view.
        """
        # Step 1: Extract and sanitize text inputs
        raw_name = self.window.txtFormName.text().strip()
        raw_host = self.window.txtFormHost.text().strip()

        # Sanitize host: strip protocol schemes, paths, and extract embedded port
        parsed = urlsplit(raw_host if "//" in raw_host else f"//{raw_host}")
        clean_host = parsed.hostname or raw_host.split("/")[0].split(":")[0].strip()
        embedded_port = parsed.port

        check_type = self.window.cmbFormType.currentText().strip().upper()

        # Step 2: Determine port value
        if check_type == "TCP":
            # Prefer embedded port if typed in host box, otherwise read spinbox
            port_val = embedded_port if embedded_port is not None else int(self.window.spnFormPort.value())
        else:
            # PING verification does not use service ports
            port_val = None

        # Step 3: Validate mandatory inputs
        if not raw_name or not clean_host:
            QMessageBox.warning(
                self.window, "Validation Error",
                "Both Equipment Name and Host Address are required to configure a server."
            )
            return

        # Step 4: Branch on EDIT vs ADD mode
        if self.editing_target_id is not None:
            # =================================================================
            # BRANCH A: EDITING AN EXISTING TARGET
            # =================================================================
            target = self.target_lookup.get(self.editing_target_id)
            if target:
                target["name"] = raw_name

                # If the host changed, clear cached DNS and status to prevent stale telemetry
                if target.get("host") != clean_host:
                    target["resolved_ip"] = None
                    target["status"] = "PENDING"
                    target["response_time_ms"] = None
                    target["tcp_status"] = "STANDBY"
                    target["tcp_latency_ms"] = None
                    target["icmp_status"] = "STANDBY"
                    target["icmp_latency_ms"] = None
                    target["latency_delta_ms"] = None
                    target["delta_analysis"] = "Run verification to compute protocol delta"
                    target["error"] = None
                    target["last_checked"] = None

                target["host"] = clean_host
                target["check_type"] = check_type
                target["port"] = port_val

                # Ensure all modern dual-protocol and counter keys exist on the target
                for k, v in storageH.create_target_entry("", "", "").items():
                    target.setdefault(k, v)

                # If this server is currently open in the Inspector, refresh its display
                if self.current_inspected_id == target.get("id"):
                    self.populate_server_detail_page(target["id"])

        else:
            new_entry = storageH.create_target_entry(
                name=raw_name,
                host=clean_host,
                check_type=check_type,
                port=port_val
            )
            self.targets.append(new_entry)

        # Step 5: Commit to disk immediately
        storageH.save_targets(self.targets)

        # Step 6: Reload memory lookup dictionaries, rebuild tables, and update autocompleter
        self.load_target_data()
        self.setup_search_autocomplete()

        # Step 7: Return the user back to the All Devices view (page index 1)
        self.editing_target_id = None
        self.switch_page(1, self.window.btnNavServers)

    def cancel_server_form(self):
        """Aborts current edit and returns user back to the All Devices directory."""
        self.editing_target_id = None
        self.switch_page(1, self.window.btnNavServers)

    def delete_selected_server(self):
        """Prompts confirmation and removes the selected server entry from targets.json."""
        selected_id = self.get_selected_server_id()
        if not selected_id:
            QMessageBox.information(
                self.window, "Selection Required",
                "Please select a server row from the table to delete."
            )
            return

        target = self.target_lookup.get(selected_id)
        if not target:
            return

        reply = QMessageBox.question(
            self.window,
            "Confirm Server Removal",
            f"Are you sure you want to remove '{target.get('name')}' ({target.get('host')}) from monitoring?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            # Stop the scheduler timer for the deleted server
            self.scheduler.stop_server_scheduler(selected_id)

            self.targets = [t for t in self.targets if t.get("id") != selected_id]
            storageH.save_targets(self.targets)

            self.load_target_data()
            self.setup_search_autocomplete()

    def get_selected_server_id(self) -> str:
        """Helper to extract the unique target ID stored in UserRole from the current row."""
        current_row = self.window.tblAllServers.currentRow()
        if current_row < 0:
            return None

        name_item = self.window.tblAllServers.item(current_row, 0)
        if name_item:
            return name_item.data(Qt.UserRole)
        return None


    # =========================================================================
    # SEARCH & TABLE FILTERING
    # =========================================================================

    def setup_table_filters(self):
        """Binds toolbar search edit and filter combo boxes to the table filter method."""
        self.window.txtServerSearch.textChanged.connect(self.filter_servers_table)
        self.window.cmbFilterType.currentTextChanged.connect(self.filter_servers_table)
        self.window.cmbFilterStatus.currentTextChanged.connect(self.filter_servers_table)

    def filter_servers_table(self):
        """Hides or reveals table rows based on search text, protocol, and reachability status."""
        search_query = self.window.txtServerSearch.text().strip().lower()
        type_filter = self.window.cmbFilterType.currentText().upper()
        status_filter = self.window.cmbFilterStatus.currentText().upper()

        table = self.window.tblAllServers
        visible_count = 0

        for row in range(table.rowCount()):
            name_text = table.item(row, 0).text().lower() if table.item(row, 0) else ""
            host_text = table.item(row, 1).text().lower() if table.item(row, 1) else ""
            type_text = table.item(row, 3).text().upper() if table.item(row, 3) else ""
            status_text = table.item(row, 5).text().upper() if table.item(row, 5) else ""

            matches_search = (search_query in name_text) or (search_query in host_text) if search_query else True
            matches_type = (type_filter == "ALL TYPES") or (type_filter == type_text)
            matches_status = (status_filter == "ALL STATUS") or (status_filter == status_text)

            row_visible = matches_search and matches_type and matches_status
            table.setRowHidden(row, not row_visible)

            if row_visible:
                visible_count += 1

        self.window.lblTotalCountSummary.setText(f"Showing {visible_count} of {len(self.targets)} registered servers")


    # =========================================================================
    # NAVIGATION & AUTOCOMPLETE
    # =========================================================================

    def setup_navigation(self):
        """Maps sidebar buttons to their respective stackedWidget page indexes."""
        self.nav_buttons = [
            (self.window.btnNavDashboard, 0),
            (self.window.btnNavServers, 1),
            (self.window.btnNavDetails, 2),
            (self.window.btnNavLogs, 3),
            (self.window.btnNavSettings, 4),
            (self.window.btnNavResources, 6)
        ]

        for button, page_index in self.nav_buttons:
            button.clicked.connect(lambda checked=False, idx=page_index, btn=button: self.switch_page(idx, btn))

        # Default view is Dashboard
        self.switch_page(0, self.window.btnNavDashboard)

    def setup_actions(self):
        """Connects UI buttons to their handlers."""
        # Restore and auto-save default protocol on top toolbar
        saved_proto = self.settings.get("default_protocol", "TCP")
        self.window.cmbHeaderCheckType.setCurrentText(saved_proto)
        self.window.cmbHeaderCheckType.currentTextChanged.connect(
            lambda proto: self.settings.set("default_protocol", proto)
        )

        # Batch Check Triggers
        self.window.btnCheckNow.clicked.connect(self.trigger_manual_check)
        self.window.btnManualRefreshLogs.clicked.connect(self.refresh_logs)

        # Dashboard Quick Inspector Trigger (Tests ONLY the selected dashboard host)
        self.window.btnManualCheckNow.clicked.connect(self.test_dashboard_quick_target)
        self.window.cmbQuickTarget.currentIndexChanged.connect(self.handle_quick_target_changed)
        if hasattr(self.window, "btnQuickOpenDetails"):
            self.window.btnQuickOpenDetails.clicked.connect(self.open_quick_target_detail)

        # Inspector Actions: Dedicated Dual Protocol Triggers
        self.window.btnDetailBackToServers.clicked.connect(lambda: self.switch_page(1, self.window.btnNavServers))
        self.window.btnDetailTestIcmp.clicked.connect(self.test_single_icmp)
        self.window.btnDetailTestTcp.clicked.connect(self.test_single_tcp)
        self.window.btnDetailTestNow.clicked.connect(self.test_single_both)

        # CRUD Actions
        self.window.btnAddDevice.clicked.connect(self.open_add_server_form)
        self.window.btnPageAddDevice.clicked.connect(self.open_add_server_form)
        self.window.btnEditDevice.clicked.connect(self.open_edit_server_form)
        self.window.btnDeleteDevice.clicked.connect(self.delete_selected_server)

        # Form Actions
        self.window.btnFormSave.clicked.connect(self.save_server_form)
        self.window.btnFormCancel.clicked.connect(self.cancel_server_form)
        self.window.cmbFormType.currentTextChanged.connect(self.handle_form_type_change)

    def setup_search_autocomplete(self):
        """Binds QCompleter on txtGlobalSearch to target names and hosts."""
        search_entries = [f"{t.get('name')} | {t.get('host')}" for t in self.targets]
        self.search_model = QStringListModel(search_entries)
        self.completer = QCompleter(self.search_model, self.window.txtGlobalSearch)
        self.completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.completer.setFilterMode(Qt.MatchContains)
        self.window.txtGlobalSearch.setCompleter(self.completer)

        self.completer.activated.connect(self.handle_search_selection)
        self.window.txtGlobalSearch.returnPressed.connect(self.handle_search_enter)

    def handle_search_selection(self, selected_text: str):
        """Navigates to Server Inspector when clicking an autocomplete item."""
        for t in self.targets:
            candidate = f"{t.get('name')} | {t.get('host')}"
            if candidate == selected_text or t.get("name") in selected_text or t.get("host") in selected_text:
                self.populate_server_detail_page(t.get("id"))
                self.switch_page(2, self.window.btnNavDetails)
                break

    def handle_search_enter(self):
        """Navigates to Server Inspector upon hitting Enter in the global search bar."""
        query = self.window.txtGlobalSearch.text().strip().lower()
        if not query:
            return

        for t in self.targets:
            if query in t.get("name", "").lower() or query in t.get("host", "").lower():
                self.populate_server_detail_page(t.get("id"))
                self.switch_page(2, self.window.btnNavDetails)
                break

    def _open_row_inspector(self, table, row: int):
        """Opens double-clicked row from table in Server Inspector."""
        item = table.item(row, 0)
        if item and item.data(Qt.UserRole):
            self.populate_server_detail_page(item.data(Qt.UserRole))
            self.switch_page(2, self.window.btnNavDetails)

    def handle_quick_target_changed(self, index: int):
        """Fires when user selects a different target in the Dashboard combobox."""
        target_id = self.window.cmbQuickTarget.currentData()
        if target_id:
            self.update_dashboard_quick_target_card(target_id)

    def update_dashboard_quick_target_card(self, target_id: str):
        """
        Refreshes the Dashboard Quick Inspector panel with current metrics for the host.

        Educational Context:
        - This card displays live operational health for whichever server the operator
          selects in `cmbQuickTarget`.
        - Crucially, background checks and batch runs only invoke this method if the target
          tested matches `cmbQuickTarget.currentData()`. This guarantees the card does NOT
          jump or flicker with irrelevant data when other servers are being checked.
        - The visual progress bar (`barQuickAvailability`) gives instant health assessment:
          * Green (#10b981) >= 95% availability (Reliable)
          * Amber (#f59e0b) >= 80% availability (Degraded/Lossy)
          * Red   (#ef4444) < 80% availability (Critical)
        """
        target = self.target_lookup.get(target_id)
        if not target:
            return

        # Status Label
        status = target.get("status", "READY")
        lat = target.get("response_time_ms")
        lat_str = f" ({lat}ms)" if lat is not None else ""
        self.window.lblInfoStatus.setText(f"Status: {status}{lat_str}")

        color = STATUS_COLORS.get(status, "#94a3b8")
        self.window.lblInfoStatus.setStyleSheet(f"color: {color}; font-weight: 700;")

        # Resolved IP
        self.window.lblInfoResolved.setText(f"Resolved IP: {target.get('resolved_ip') or '-'}")

        # Individual Protocols
        icmp_lat = target.get("icmp_latency_ms")
        tcp_lat = target.get("tcp_latency_ms")
        icmp_st = target.get("icmp_status", "Standby")
        tcp_st = target.get("tcp_status", "Standby")

        self.window.lblInfoIcmp.setText(f"ICMP Ping: {icmp_lat} ms ({icmp_st})" if icmp_lat is not None else f"ICMP Ping: -- ms ({icmp_st})")
        self.window.lblInfoTcp.setText(f"TCP Service: {tcp_lat} ms ({tcp_st})" if tcp_lat is not None else f"TCP Service: -- ms ({tcp_st})")

        # Checks & Uptime Summary
        succ = target.get("successes", 0)
        fail = target.get("failures", 0)
        tot = succ + fail
        pct = round((succ / tot) * 100, 1) if tot > 0 else 100.0
        self.window.lblInfoStats.setText(f"Checks: {succ} OK / {fail} Failures ({pct}%)")

        # Visual Aid: Availability Progress Bar & Percentage Metric
        bar_color = "#10b981" if pct >= 95.0 else ("#f59e0b" if pct >= 80.0 else "#ef4444")
        if hasattr(self.window, "lblQuickUptime"):
            self.window.lblQuickUptime.setText(f"{pct}%")
            self.window.lblQuickUptime.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {bar_color};")

        if hasattr(self.window, "barQuickAvailability"):
            self.window.barQuickAvailability.setValue(int(pct))
            self.window.barQuickAvailability.setStyleSheet(
                f"QProgressBar {{ background-color: #1e293b; border: 1px solid #334155; border-radius: 4px; height: 10px; }} "
                f"QProgressBar::chunk {{ background-color: {bar_color}; border-radius: 3px; }}"
            )

    def test_dashboard_quick_target(self):
        """Runs an immediate verification on the target selected in the Dashboard Quick panel."""
        target_id = self.window.cmbQuickTarget.currentData()
        if not target_id:
            return

        self.current_inspected_id = target_id
        self.test_single_both()

    def open_quick_target_detail(self):
        """
        Directly switches to Page 2 (Server Diagnostics / Server Inspector)
        focused on the currently selected host from the Dashboard Quick Inspector.

        Educational Context:
        - Provides immediate 1-click drilldown into complete protocol delta analysis,
          latency telemetry, and hardware slots for the endpoint being viewed.
        - Avoids requiring the user to switch tabs manually and look up the server.
        """
        target_id = self.window.cmbQuickTarget.currentData()
        if not target_id:
            return

        self.populate_server_detail_page(target_id)
        self.switch_page(2, self.window.btnNavDetails)


    # =========================================================================
    # DUAL-PROTOCOL SERVER INSPECTOR LOGIC
    # =========================================================================

    def populate_server_detail_page(self, target_id: str):
        """
        Populates pageServerDetail with dual ICMP vs TCP metrics, protocol delta,
        historical response telemetry, and system uptime percentages.
        """
        target = self.target_lookup.get(target_id)
        if not target:
            return

        self.current_inspected_id = target_id

        # Headers & Identifiers
        self.window.lblDetServerName.setText(target.get("name", "Unknown Server"))
        self.window.lblDetServerHost.setText(f"Host: {target.get('host')} | ID: {target.get('id')}")

        # Overall Status Badge
        status = target.get("status", "PENDING")
        self.window.lblDetStatusBadge.setText(status)
        badge_styles = {
            "ONLINE": "background-color: #064e3b; color: #34d399; font-weight: 700; padding: 6px 16px; border-radius: 8px;",
            "OFFLINE": "background-color: #7f1d1d; color: #f87171; font-weight: 700; padding: 6px 16px; border-radius: 8px;",
        }
        self.window.lblDetStatusBadge.setStyleSheet(
            badge_styles.get(status, "background-color: #1e293b; color: #94a3b8; font-weight: 700; padding: 6px 16px; border-radius: 8px;")
        )

        # Primary Latency & Historical Averages
        last_lat = target.get("response_time_ms")
        self.window.lblValDetLat.setText(f"{last_lat} ms" if last_lat is not None else "-- ms")

        avg_lat = target.get("avg_response_time_ms")
        self.window.lblValDetAvgLat.setText(f"{avg_lat} ms" if avg_lat is not None else "-- ms")

        # ICMP and TCP Individual Latencies
        icmp_lat = target.get("icmp_latency_ms")
        tcp_lat = target.get("tcp_latency_ms")

        self.window.lblValDetIcmpLat.setText(f"{icmp_lat} ms" if icmp_lat is not None else "-- ms")
        self.window.lblValDetTcpLat.setText(f"{tcp_lat} ms" if tcp_lat is not None else "-- ms")

        # Latency Delta Calculation: Handshake Delta = TCP - ICMP
        delta_val = target.get("latency_delta_ms")
        if delta_val is not None:
            self.window.lblValDetDelta.setText(f"+{delta_val} ms" if delta_val >= 0 else f"{delta_val} ms")
        else:
            self.window.lblValDetDelta.setText("-- ms")

        # Update Secondary Protocol Badges
        icmp_res = target.get("icmp_status", "STANDBY")
        tcp_res = target.get("tcp_status", "STANDBY")

        self.window.lblDetIcmpBadge.setText(f"PING: {icmp_res}")
        self.window.lblDetTcpBadge.setText(f"TCP: {tcp_res}")

        # Successes, Failures & Uptime Percentage
        # Overall Uptime Percentage
        succ = target.get("successes", 0)
        fail = target.get("failures", 0)
        total = succ + fail
        uptime_pct = round((succ / total) * 100, 1) if total > 0 else 100.0
        self.window.lblValDetUptime.setText(f"{uptime_pct}%")

        # Slot 1: Dedicated TCP Checks Counter
        tcp_ok = target.get("tcp_successes", 0)
        tcp_fail = target.get("tcp_failures", 0)
        tcp_total = tcp_ok + tcp_fail
        self.window.lblValDetTcpChecks.setText(f"{tcp_ok} / {tcp_total}")

        # Slot 2: Dedicated Ping Checks Counter
        ping_ok = target.get("ping_successes", 0)
        ping_fail = target.get("ping_failures", 0)
        ping_total = ping_ok + ping_fail
        self.window.lblValDetPingChecks.setText(f"{ping_ok} / {ping_total}")

        # Protocol Diagnostics (TCP / ICMP)
        self.window.lblDetSpecPort.setText(str(target.get("port") or "N/A"))
        self.window.lblDetSpecType.setText(target.get("check_type", "N/A"))

        tcp_status = target.get("tcp_status") or "Not Tested"
        self.window.lblDetTcpResult.setText(str(tcp_status))
        self.window.lblDetTcpResult.setStyleSheet(f"color: {STATUS_COLORS.get(tcp_status, '#94a3b8')}; font-weight: 700;")

        # --- SECTION 2 (BOTTOM): ICMP Ping & Link Telemetry ---
        # Ensure wordWrap is enabled on all dynamic text labels so text moves
        # to the line below rather than pushing the panel wider
        self.window.lblDetSpecResolved.setWordWrap(True)
        self.window.lblDetDeltaAnalysis.setWordWrap(True)
        self.window.lblDetSpecError.setWordWrap(True)

        self.window.lblDetSpecResolved.setText(target.get("resolved_ip") or "Unresolved")

        icmp_status = target.get("icmp_status") or "Not Tested"
        self.window.lblDetIcmpResult.setText(str(icmp_status))
        self.window.lblDetIcmpResult.setStyleSheet(f"color: {STATUS_COLORS.get(icmp_status, '#94a3b8')}; font-weight: 700;")

        self.window.lblDetSpecLast.setText(target.get("last_checked") or "Never")

        # Detailed protocol overhead delta narrative
        delta_msg = target.get("delta_analysis", "Run 'Run Both Tests' to evaluate TCP handshake overhead vs ICMP link speed.")
        self.window.lblDetDeltaAnalysis.setText(delta_msg)

        # Operational error or normal message
        err = target.get("error")
        if err:
            self.window.lblDetSpecError.setText(err)
            self.window.lblDetSpecError.setStyleSheet("color: #ef4444; font-weight: 500;")
        else:
            self.window.lblDetSpecError.setText("None - System Operating Normally")
            self.window.lblDetSpecError.setStyleSheet("color: #10b981; font-weight: 500;")

    def _ensure_active_inspected_target(self) -> dict:
        """Helper ensuring self.current_inspected_id points to a valid target."""
        if not self.current_inspected_id:
            selected_row_id = self.get_selected_server_id()
            if selected_row_id:
                self.current_inspected_id = selected_row_id
            elif self.targets:
                self.current_inspected_id = self.targets[0]["id"]
            else:
                return None
        return self.target_lookup.get(self.current_inspected_id)

    def _launch_single_worker(self, mode: str):
        """
        Shared launcher for all three inspector buttons.

        This method is the bridge between a button click and the background thread.
        It validates state, disables the test buttons so the user can't fire two
        overlapping checks, creates a SingleTargetWorker, connects its signal, and
        starts it. The buttons re-enable automatically in _handle_single_check_finished
        once the result arrives.

        Parameters:
            mode - "PING", "TCP", or "BOTH" -- passed directly to SingleTargetWorker.
        """
        # If a single-target check is already running, ignore the new click.
        # This prevents overlapping network calls that would produce confusing results.
        if self.single_worker is not None and self.single_worker.isRunning():
            return

        # Validate that we have a target to test
        target = self._ensure_active_inspected_target()
        if not target:
            return

        # Disable all three inspector test buttons while the check is in flight.
        # This gives clear visual feedback that a check is happening.
        self.window.btnDetailTestIcmp.setEnabled(False)
        self.window.btnDetailTestTcp.setEnabled(False)
        self.window.btnDetailTestNow.setEnabled(False)

        # Create and configure the background worker thread
        self.single_worker = SingleTargetWorker(
            target=target,
            mode=mode,
            timeout=self.check_timeout
        )

        # Connect the signal BEFORE calling start().
        # The lambda captures `target` by reference so the result handler
        # can write results directly into the same dict that the lookup holds.
        self.single_worker.check_finished.connect(
            lambda payload, t=target: self._handle_single_check_finished(payload, t)
        )

        # This launches the worker's run() method on the background thread.
        self.single_worker.start()

    def test_single_icmp(self):
        """
        Triggered by the 'Ping Test' inspector button.
        Offloads the ICMP echo check to a background thread so the GUI stays responsive.
        """
        self._launch_single_worker("PING")

    def test_single_tcp(self):
        """
        Triggered by the 'TCP Test' inspector button.
        Offloads the TCP handshake check to a background thread so the GUI stays responsive.
        """
        self._launch_single_worker("TCP")

    def test_single_both(self):
        """
        Triggered by the 'Inspect and Test' inspector button.
        Offloads both ICMP and TCP checks sequentially to a background thread.
        The delta calculation runs after both results are in.
        """
        self._launch_single_worker("BOTH")

    def _handle_single_check_finished(self, payload: dict, target: dict, source: str = "MANUAL"):
        """
        Called automatically on the MAIN THREAD (via Qt signal) once
        the SingleTargetWorker background thread completes its check.
        
        Parameters:
            payload - Dict from SingleTargetWorker.check_finished
            target  - The target dict to update in-place
            source  - 'SCHEDULED' if triggered by ServerScheduler timer, else 'MANUAL'
        """
        # Re-enable the inspector buttons now that the check has finished
        self.window.btnDetailTestIcmp.setEnabled(True)
        self.window.btnDetailTestTcp.setEnabled(True)
        self.window.btnDetailTestNow.setEnabled(True)

        mode     = payload["mode"]
        ping_res = payload.get("ping_res")
        tcp_res  = payload.get("tcp_res")
        now      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # --- Apply PING and TCP results ---
        for proto, res in [("PING", ping_res), ("TCP", tcp_res)]:
            if res is None:
                continue
            prefix = "icmp" if proto == "PING" else "tcp"
            target[f"{prefix}_status"] = res["status"]
            target[f"{prefix}_latency_ms"] = res["response_time_ms"]
            target["last_checked"] = now
            if res.get("resolved_ip"):
                target["resolved_ip"] = res["resolved_ip"]
            self._update_target_counters(
                target, res["status"], res["response_time_ms"], check_mode=proto
            )
            self._log_and_append_result(target, proto, res)

        # Update primary status and Last Latency based on whichever test was triggered
        primary_res = None
        if mode == "PING":
            primary_res = ping_res
        elif mode == "TCP":
            primary_res = tcp_res
        else:  # "BOTH"
            preferred = target.get("check_type", "TCP").upper()
            primary_res = tcp_res if preferred == "TCP" and tcp_res else ping_res
            if not primary_res:
                primary_res = tcp_res or ping_res

        if primary_res:
            target["status"] = primary_res["status"]
            target["response_time_ms"] = primary_res["response_time_ms"]
            target["error"] = primary_res.get("error")

        # --- Recompute delta and refresh all views ---
        self._recompute_delta_and_update(target)

        # Record storage attribution to monitor.log (SCHEDULED vs MANUAL)
        self.record_log_growth(source=source)

        # Notify scheduler so it dynamically adjusts interval:
        # - ONLINE  -> 60 seconds (normal)
        # - OFFLINE -> 30 seconds (tightened)
        if target.get("id"):
            self.scheduler.update_status(target.get("id"), target.get("status"))

    def _update_target_counters(self, target: dict, status: str, latency: float, check_mode: str = "TCP"):
        """Helper to increment general and protocol-specific counters."""
        is_online = (status == "ONLINE")

        # Global Counters
        if is_online:
            target["successes"] = target.get("successes", 0) + 1
            if latency is not None:
                tot = target.get("total_response_time_ms", 0.0) + latency
                target["total_response_time_ms"] = tot
                target["avg_response_time_ms"] = round(tot / target["successes"], 2)
        else:
            target["failures"] = target.get("failures", 0) + 1

        # Protocol-Specific Counters for the Dual Slots
        if "TCP" in check_mode.upper():
            if is_online:
                target["tcp_successes"] = target.get("tcp_successes", 0) + 1
            else:
                target["tcp_failures"] = target.get("tcp_failures", 0) + 1
        elif "PING" in check_mode.upper():
            if is_online:
                target["ping_successes"] = target.get("ping_successes", 0) + 1
            else:
                target["ping_failures"] = target.get("ping_failures", 0) + 1

    def _log_and_append_result(self, target: dict, mode: str, res: dict):
        """Appends audit record directly into the live Audit Logs console."""
        log_line = res.get("log_entry")
        if not log_line:
            check_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            equipment = target.get("name", "Unknown") if target else "Unknown"
            host_str = target.get("host", "Unknown") if target else "Unknown"
            resolved_ip = res.get("resolved_ip") or "Unresolved"
            check_type = res.get("check_type") or mode
            port = res.get("port") or (target.get("port", 80) if str(check_type).upper() == "TCP" else "N/A")
            status = res.get("status", "UNKNOWN")
            lat = res.get("response_time_ms")
            elapsed = f"{lat}ms" if lat is not None else "N/A"
            err = res.get("error") or "None"
            lvl = "INFO" if status == "ONLINE" else "WARNING"
            log_line = (
                f"{check_time} - {lvl} - "
                f"EQUIPMENT: {equipment} | "
                f"HOST: {host_str} (IP: {resolved_ip}) | "
                f"TYPE: {check_type} | "
                f"PORT: {port} | "
                f"RESULT: {status} | "
                f"TIME: {elapsed} | "
                f"ERROR: {err}"
            )
        self.window.txt_audit_logs.append(log_line)

    def _recompute_delta_and_update(self, target: dict):
        """
        Calculates Protocol Overhead Delta (TCP - ICMP) and updates all connected UI views.
        """
        icmp_lat = target.get("icmp_latency_ms")
        tcp_lat = target.get("tcp_latency_ms")

        if icmp_lat is not None and tcp_lat is not None:
            delta = round(tcp_lat - icmp_lat, 2)
            target["latency_delta_ms"] = delta
            if delta >= 0:
                target["delta_analysis"] = f"TCP handshake adds +{delta}ms overhead over raw ICMP ping."
            else:
                target["delta_analysis"] = f"TCP responded {abs(delta)}ms faster (routing divergence / ICMP deprioritization)."
        elif target.get("tcp_status") == "OFFLINE" and target.get("icmp_status") == "ONLINE":
            target["latency_delta_ms"] = None
            target["delta_analysis"] = "Host responds to ICMP Ping, but TCP port connection is closed or blocked."
        elif target.get("icmp_status") == "OFFLINE" and target.get("tcp_status") == "ONLINE":
            target["latency_delta_ms"] = None
            target["delta_analysis"] = "TCP port is open and online, but host blocks ICMP echo requests."
        elif target.get("tcp_status") == "OFFLINE" and target.get("icmp_status") == "OFFLINE":
            target["latency_delta_ms"] = None
            target["delta_analysis"] = "Host is completely unreachable on both ICMP and TCP protocols."
        else:
            target["latency_delta_ms"] = None
            target["delta_analysis"] = "Run 'Inspect & Test' to evaluate TCP handshake overhead vs ICMP link speed."

        # Commit target update and render
        self.schedule_disk_save()
        self.update_single_server_row_in_place(target)
        self.update_dashboard_stat_cards()

        # Update Inspector if viewing this target
        if self.current_inspected_id == target.get("id"):
            self.populate_server_detail_page(target["id"])

        # Update Recent Servers list
        if target in self.recent_targets:
            self.recent_targets.remove(target)
        self.recent_targets.insert(0, target)
        self.populate_recent_servers_table()

        # Sync dashboard quick inspector view ONLY if this target is the currently selected one
        selected_quick_id = self.window.cmbQuickTarget.currentData()
        if target.get("id") == selected_quick_id:
            self.update_dashboard_quick_target_card(target["id"])


    # =========================================================================
    # SETTINGS PAGE & WORKER CONCURRENCY CONFIGURATION
    # =========================================================================

    def setup_settings_page(self):
        """
        Constructs the configuration card within Page 4 (Application Settings).
        Includes thread worker count selection, dynamic resource advice banners,
        and socket verification timeout controls.
        """
        layout = self.window.p4_layout

        # Settings Panel Frame
        frame_settings = QFrame()
        frame_settings.setStyleSheet(
            "background-color: #131d33; border: 1px solid #1e293b; border-radius: 12px; padding: 20px;"
        )
        frame_layout = QVBoxLayout(frame_settings)
        frame_layout.setSpacing(16)

        # Setting 1: Thread Worker Concurrency Selector
        lbl_workers_title = QLabel("Concurrent Verification Workers:")
        lbl_workers_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff;")
        frame_layout.addWidget(lbl_workers_title)

        self.cmb_workers = QComboBox()

        # --- Worker Tier Options ---
        # Each addItem call adds one option to the dropdown.
        # The first argument is the human-readable label shown to the user.
        # The second argument (the integer) is the actual data value -- the number
        # of concurrent worker threads that will be passed to ThreadPoolExecutor.
        # Qt lets us attach this hidden value to each item so we can retrieve it
        # later with currentData() instead of parsing the label text.

        # Setting 1: Thread Worker Concurrency (Text Box + Confirmation)
        lbl_workers_title = QLabel("Concurrent Verification Workers:")
        lbl_workers_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff;")
        frame_layout.addWidget(lbl_workers_title)

        workers_row = QHBoxLayout()
        self.txt_workers = QLineEdit(str(self.max_workers))
        self.txt_workers.setPlaceholderText("e.g. 16, 24, 32...")
        self.txt_workers.setStyleSheet(
            "background-color: #1e293b; border: 1px solid #334155; padding: 8px 12px; font-weight: 600; border-radius: 6px;"
        )
        self.btn_apply_workers = QPushButton("Confirm & Apply Workers")
        self.btn_apply_workers.setStyleSheet(
            "background-color: #2563eb; color: #ffffff; padding: 8px 16px; font-weight: 700; border-radius: 6px;"
        )
        self.btn_apply_workers.clicked.connect(self.handle_apply_custom_workers)
        workers_row.addWidget(self.txt_workers)
        workers_row.addWidget(self.btn_apply_workers)
        frame_layout.addLayout(workers_row)

        # Dynamic Advice / Safety Banner
        self.lbl_worker_advice = QLabel()
        self.lbl_worker_advice.setWordWrap(True)
        self._update_worker_advice_banner(self.max_workers)
        frame_layout.addWidget(self.lbl_worker_advice)

        # Setting 2: Network Timeout
        lbl_timeout_title = QLabel("Network Connection Timeout (Seconds):")
        lbl_timeout_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff; margin-top: 10px;")
        frame_layout.addWidget(lbl_timeout_title)

        self.spn_timeout = QSpinBox()
        self.spn_timeout.setRange(1, 15)
        self.spn_timeout.setValue(int(self.check_timeout))
        self.spn_timeout.setStyleSheet(
            "background-color: #1e293b; border: 1px solid #334155; padding: 6px 12px; font-weight: 600; border-radius: 6px;"
        )
        self.spn_timeout.valueChanged.connect(self.handle_timeout_setting_change)
        frame_layout.addWidget(self.spn_timeout)

        # Setting 3: Scheduler Timers (Online vs Offline Intervals)
        lbl_intervals_title = QLabel("Server Scheduling Cadence (Seconds):")
        lbl_intervals_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff; margin-top: 10px;")
        frame_layout.addWidget(lbl_intervals_title)

        intervals_row = QHBoxLayout()
        # Normal (Online) interval
        col_online = QVBoxLayout()
        col_online.addWidget(QLabel("Online Server Interval (Sec):"))
        self.spn_online_interval = QSpinBox()
        self.spn_online_interval.setRange(5, 3600)
        self.spn_online_interval.setValue(self.online_interval)
        self.spn_online_interval.setStyleSheet("background-color: #1e293b; border: 1px solid #334155; padding: 6px 12px; font-weight: 600; border-radius: 6px;")
        self.spn_online_interval.valueChanged.connect(self.handle_interval_change)
        col_online.addWidget(self.spn_online_interval)
        intervals_row.addLayout(col_online)

        # Offline (Tightened) interval
        col_offline = QVBoxLayout()
        col_offline.addWidget(QLabel("Offline / Down Server Interval (Sec):"))
        self.spn_offline_interval = QSpinBox()
        self.spn_offline_interval.setRange(5, 3600)
        self.spn_offline_interval.setValue(self.offline_interval)
        self.spn_offline_interval.setStyleSheet("background-color: #1e293b; border: 1px solid #334155; padding: 6px 12px; font-weight: 600; border-radius: 6px;")
        self.spn_offline_interval.valueChanged.connect(self.handle_interval_change)
        col_offline.addWidget(self.spn_offline_interval)
        intervals_row.addLayout(col_offline)
        frame_layout.addLayout(intervals_row)

        # Setting 4: Resource Monitor Refresh Rate
        lbl_monitor_speed_title = QLabel("App Resource Monitor Speed / Refresh Rate:")
        lbl_monitor_speed_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff; margin-top: 10px;")
        frame_layout.addWidget(lbl_monitor_speed_title)

        self.cmb_monitor_speed = QComboBox()
        self.cmb_monitor_speed.addItem("Fast / High Fidelity (500ms)", 500)
        self.cmb_monitor_speed.addItem("Rapid (1000ms / 1 Second)", 1000)
        self.cmb_monitor_speed.addItem("Normal Default (2000ms / 2 Seconds)", 2000)
        self.cmb_monitor_speed.addItem("Low Power / Minimal (5000ms / 5 Seconds)", 5000)
        self.cmb_monitor_speed.setStyleSheet(
            "background-color: #1e293b; border: 1px solid #334155; padding: 8px 12px; font-weight: 600; border-radius: 6px;"
        )
        # Select currently configured speed
        idx = self.cmb_monitor_speed.findData(self.monitor_refresh_ms)
        self.cmb_monitor_speed.setCurrentIndex(max(0, idx))
        self.cmb_monitor_speed.currentIndexChanged.connect(self.handle_monitor_speed_change)
        frame_layout.addWidget(self.cmb_monitor_speed)

        # Insert Settings card above the bottom spacer in p4_layout
        layout.insertWidget(2, frame_settings)

    def _update_worker_advice_banner(self, workers: int):
        """Displays descriptive feedback banner based on the worker count."""
        if workers <= 8:
            text = f"Standard Mode ({workers} Workers): Gentle load. Recommended for light systems."
            style = "background-color: #0f172a; border-left: 4px solid #10b981; padding: 10px; color: #94a3b8; font-size: 12px;"
        elif workers <= 24:
            text = f"Moderate / High Load ({workers} Workers): Fast throughput with manageable socket pressure."
            style = "background-color: #0f172a; border-left: 4px solid #38bdf8; padding: 10px; color: #cbd5e1; font-size: 12px;"
        elif workers <= 64:
            text = f"Aggressive Concurrency ({workers} Workers): High parallelism. May increase brief CPU and router traffic."
            style = "background-color: #1e111a; border-left: 4px solid #f59e0b; padding: 10px; color: #fde68a; font-size: 12px;"
        else:
            text = f"Extreme Concurrency ({workers} Workers): Very high thread count. Ensure router NAT tables can sustain this load."
            style = "background-color: #2a111a; border-left: 4px solid #ef4444; padding: 10px; color: #fca5a5; font-size: 12px;"

        self.lbl_worker_advice.setText(text)
        self.lbl_worker_advice.setStyleSheet(style)

    def handle_apply_custom_workers(self):
        """
        Validates text input, prompts confirmation to prevent accidental huge numbers,
        updates self.max_workers, and persists to config/settings.json.
        """
        raw_val = self.txt_workers.text().strip()
        try:
            val = int(raw_val)
            if val < 1:
                raise ValueError("Must be at least 1")
        except ValueError:
            QMessageBox.warning(
                self.window, "Invalid Number",
                "Please enter a valid positive integer for the number of workers (e.g. 16, 24, 32)."
            )
            self.txt_workers.setText(str(self.max_workers))
            return

        # Confirmation dialog for safety
        if val > 64:
            reply = QMessageBox.question(
                self.window, "High Worker Warning",
                f"Setting concurrency to {val} simultaneous worker threads can saturate home router NAT tables or open socket handles.\n\nAre you sure you want to proceed?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                self.txt_workers.setText(str(self.max_workers))
                return

        self.max_workers = val
        self.settings.set("max_workers", val)
        self._update_worker_advice_banner(val)
        QMessageBox.information(
            self.window, "Settings Updated",
            f"Successfully updated worker concurrency to {val} threads."
        )

    def handle_interval_change(self):
        """Updates online and offline scheduler intervals and saves to disk."""
        self.online_interval = self.spn_online_interval.value()
        self.offline_interval = self.spn_offline_interval.value()

        self.settings.set("online_interval", self.online_interval)
        self.settings.set("offline_interval", self.offline_interval)

        # Notify active ServerScheduler to adjust live timers
        self.scheduler.set_intervals(self.online_interval, self.offline_interval, targets=self.targets)

    def handle_monitor_speed_change(self, index: int):
        """Adjusts the resource monitor telemetry timer interval and auto-saves preference."""
        speed_ms = self.cmb_monitor_speed.currentData()
        if speed_ms:
            self.monitor_refresh_ms = int(speed_ms)
            self.settings.set("monitor_refresh_ms", self.monitor_refresh_ms)
            self.telemetry_timer.setInterval(self.monitor_refresh_ms)

    def handle_timeout_setting_change(self, value: int):
        """Updates internal verification timeout and AUTO-SAVES the new value to disk."""
        self.check_timeout = float(value)
        self.settings.set("check_timeout", self.check_timeout)


    # =========================================================================
    # HIGH-SPEED ASYNCHRONOUS BATCH CHECK RUNNER
    # =========================================================================

    def trigger_manual_check(self):
        """Initiates multi-threaded batch verification respecting user worker concurrency."""
        if self.worker is not None and self.worker.isRunning():
            return

        if not self.targets:
            return

        selected_mode = self.window.cmbHeaderCheckType.currentText()
        self.remaining_queue = len(self.targets)

        # Disable buttons during check
        self.window.btnCheckNow.setEnabled(False)
        self.window.lblLastCheckedHeader.setText(
            f"Queue: {self.remaining_queue} remaining ({selected_mode} @ {self.max_workers}W)..."
        )

        # Start background worker bounded strictly to user configured concurrency
        self.worker = BatchCheckWorker(
            targets=self.targets,
            selected_mode=selected_mode,
            max_workers=self.max_workers,
            timeout=self.check_timeout
        )
        self.worker.target_checked.connect(self.handle_target_checked)
        self.worker.batch_finished.connect(self.handle_batch_finished)
        self.worker.start()

    def handle_target_checked(self, payload: dict):
        """
        Executes on the main thread for every completed check.
        Performs fast in-memory mutations and targeted cell updates (under 1ms).
        """
        target_id = payload["target_id"]
        result = payload["result"]
        check_time = payload["timestamp"]

        mode = result.get("check_type", "TCP")
        target = self.target_lookup.get(target_id)
        if target:
            # 1. Update in-memory telemetry
            target["status"] = result["status"]
            target["resolved_ip"] = result["resolved_ip"]
            target["response_time_ms"] = result["response_time_ms"]
            target["last_checked"] = check_time
            target["error"] = result.get("error")

            # Update specific protocol tracker based on what was checked
            if mode == "TCP":
                target["tcp_status"] = result["status"]
                target["tcp_latency_ms"] = result["response_time_ms"]
            else:
                target["icmp_status"] = result["status"]
                target["icmp_latency_ms"] = result["response_time_ms"]

            # 2. Update math counters.
            # We pass `mode` (the active header protocol -- "TCP" or "PING") as check_mode
            # so the correct protocol-specific counter slot is incremented.
            # Without this, every batch check would always hit the TCP counter branch
            # regardless of whether PING was the selected mode.
            self._update_target_counters(target, result["status"], result["response_time_ms"], check_mode=mode)
            self._recompute_delta_and_update(target)

            # Notify scheduler so it dynamically adjusts interval:
            # - ONLINE  -> 60 seconds (normal)
            # - OFFLINE -> 30 seconds (tightened)
            if target.get("id"):
                self.scheduler.update_status(target.get("id"), target.get("status"))

        # Decrement queue countdown
        if self.remaining_queue > 0:
            self.remaining_queue -= 1
            selected_mode = self.window.cmbHeaderCheckType.currentText()
            self.window.lblLastCheckedHeader.setText(
                f"Queue: {self.remaining_queue} remaining ({selected_mode} @ {self.max_workers}W)..."
            )

        self._log_and_append_result(target, mode, result)

        # Attribute log growth to manual batch checking
        self.record_log_growth(source="MANUAL")

    def handle_batch_finished(self):
        """Fires when the complete batch of targets finishes."""
        self.flush_targets_to_disk()

        selected_mode = self.window.cmbHeaderCheckType.currentText()
        finish_time = datetime.now().strftime("%H:%M:%S")

        self.window.btnCheckNow.setEnabled(True)
        self.window.lblLastCheckedHeader.setText(f"Last check: {finish_time} ({selected_mode})")

    def switch_page(self, index: int, active_button: QPushButton):
        """Switches active stackedWidget page and updates navigation styles."""
        self.window.stackedWidget.setCurrentIndex(index)

        # If switching to Server Inspector (Index 2), ensure target is populated
        if index == 2:
            target = self._ensure_active_inspected_target()
            if target:
                self.populate_server_detail_page(target["id"])

        # If opening Audit Logs tab, do a full read to ensure external log records appear
        if index == 3:
            self.refresh_logs()

        active_style = """
            QPushButton {
                background-color: #2563eb;
                color: #ffffff;
                text-align: left;
                padding: 10px 16px;
                border-radius: 8px;
                font-weight: 600;
                border: none;
            }
        """
        inactive_style = """
            QPushButton {
                background-color: transparent;
                color: #94a3b8;
                text-align: left;
                padding: 10px 16px;
                border-radius: 8px;
                font-weight: 600;
                border: none;
            }
            QPushButton:hover {
                background-color: #1e293b;
                color: #f8fafc;
            }
        """

        for btn, _ in self.nav_buttons:
            btn.setStyleSheet(active_style if btn == active_button else inactive_style)

    def refresh_logs(self):
        """Fetches full audit logs from storageH and scrolls to the bottom."""
        raw_log_content = storageH.get_recent_logs()
        self.window.txt_audit_logs.setPlainText(raw_log_content)
        cursor = self.window.txt_audit_logs.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.window.txt_audit_logs.setTextCursor(cursor)

    # =========================================================================
    # APP RESOURCE MONITOR & LOG STORAGE ATTRIBUTION ENGINE
    # =========================================================================

    def _init_cpu_baseline(self):
        """Initializes process CPU time counter using Windows kernel32."""
        try:
            kernel32 = ctypes.WinDLL("kernel32")
            c, e, k, u = FILETIME(), FILETIME(), FILETIME(), FILETIME()
            kernel32.GetProcessTimes(kernel32.GetCurrentProcess(), ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u))
            self._prev_kernel_time = (k.dwHigh << 32) | k.dwLow
            self._prev_user_time = (u.dwHigh << 32) | u.dwLow
            self._prev_perf_time = time.perf_counter()
        except Exception:
            pass

    def _get_app_cpu_percent(self) -> float:
        """Calculates instantaneous CPU usage of this servermon process."""
        try:
            kernel32 = ctypes.WinDLL("kernel32")
            c, e, k, u = FILETIME(), FILETIME(), FILETIME(), FILETIME()
            kernel32.GetProcessTimes(kernel32.GetCurrentProcess(), ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u))
            now_kernel = (k.dwHigh << 32) | k.dwLow
            now_user = (u.dwHigh << 32) | u.dwLow
            now_perf = time.perf_counter()

            cpu_delta = ((now_kernel - self._prev_kernel_time) + (now_user - self._prev_user_time)) / 1e7
            wall_delta = now_perf - self._prev_perf_time

            self._prev_kernel_time = now_kernel
            self._prev_user_time = now_user
            self._prev_perf_time = now_perf

            if wall_delta > 0:
                pct = round((cpu_delta / wall_delta) * 100, 1)
                return max(0.0, pct)
        except Exception:
            pass
        return 0.0

    def _get_app_and_system_ram(self) -> tuple:
        """Retrieves app RAM in MB and system-wide RAM load percentage."""
        app_ram_mb = 0.0
        sys_ram_pct = 0
        try:
            psapi = ctypes.WinDLL("psapi")
            kernel32 = ctypes.WinDLL("kernel32")

            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

            pmc = PROCESS_MEMORY_COUNTERS_EX()
            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
            if psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
                app_ram_mb = round(pmc.WorkingSetSize / (1024 * 1024), 2)

            mem = MEMORYSTATUSEX()
            mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):
                sys_ram_pct = mem.dwMemoryLoad
        except Exception:
            pass

        return app_ram_mb, sys_ram_pct

    def _load_storage_metrics(self) -> dict:
        """Loads persistent storage metrics from config/log_metrics.json."""
        default_metrics = {
            "scheduled_bytes_accumulated": 0,
            "manual_bytes_accumulated": 0,
            "manual_checks_count": 0,
            "last_audit_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        if os.path.exists(self.metrics_filepath):
            try:
                with open(self.metrics_filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    default_metrics.update(data)
            except Exception:
                pass
        return default_metrics

    def _save_storage_metrics(self):
        """Persists storage metrics to disk so memory survives application closure."""
        try:
            os.makedirs(os.path.dirname(self.metrics_filepath), exist_ok=True)
            self.storage_metrics["last_audit_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self.metrics_filepath, "w", encoding="utf-8") as f:
                json.dump(self.storage_metrics, f, indent=4)
        except Exception:
            pass

    def record_log_growth(self, source: str = "SCHEDULED"):
        """
        Attributions monitor.log file expansion to either SCHEDULED or MANUAL checks.
        
        - source: 'SCHEDULED' (individual automatic timer tick) or 'MANUAL' (user clicked a test button).
        - Tracks rolling 5-minute increments for scheduled checks to project 12h/24h growth.
        """
        if not os.path.exists(self.log_filepath):
            return

        current_size = os.path.getsize(self.log_filepath)
        delta_bytes = current_size - self.last_known_log_size

        if delta_bytes > 0:
            now_ts = time.time()
            if source == "SCHEDULED":
                self.storage_metrics["scheduled_bytes_accumulated"] += delta_bytes
                # Keep rolling history for last 5 minutes (300 seconds)
                self.scheduled_history.append((now_ts, delta_bytes))
            else:
                self.storage_metrics["manual_bytes_accumulated"] += delta_bytes
                self.storage_metrics["manual_checks_count"] += 1

            self.last_known_log_size = current_size
            self._save_storage_metrics()

    def _clean_rolling_history(self):
        """Discards data points older than 5 minutes (300 seconds) from scheduled history."""
        cutoff = time.time() - 300.0
        while self.scheduled_history and self.scheduled_history[0][0] < cutoff:
            self.scheduled_history.popleft()

    def _format_size(self, num_bytes: float) -> str:
        """Formats raw bytes into human-friendly KB or MB."""
        if num_bytes < 1024:
            return f"{num_bytes:.0f} B"
        elif num_bytes < 1024 * 1024:
            return f"{num_bytes / 1024:.2f} KB"
        else:
            return f"{num_bytes / (1024 * 1024):.2f} MB"

    def update_resource_telemetry_ui(self):
        """
        Periodic UI updater invoked every 2 seconds.
        Refreshes live CPU %, RAM consumption, current log size, and projections.
        """
        # 1. Update CPU and RAM telemetry cards
        cpu_pct = self._get_app_cpu_percent()
        app_ram_mb, sys_ram_pct = self._get_app_and_system_ram()

        self.window.lblValAppCpu.setText(f"{cpu_pct:.1f} %")
        self.window.lblValAppRam.setText(f"{app_ram_mb:.1f} MB")
        self.window.lblValSysRam.setText(f"System RAM: {sys_ram_pct}% Used")

        # 2. Audit current monitor.log file size
        curr_log_size = os.path.getsize(self.log_filepath) if os.path.exists(self.log_filepath) else 0
        if curr_log_size < self.last_known_log_size:
            self.last_known_log_size = curr_log_size
        self.window.lblValLogSize.setText(self._format_size(curr_log_size))

        # 3. Compute 5-minute rolling rate for scheduled checks only
        self._clean_rolling_history()
        scheduled_window_bytes = sum(b for _, b in self.scheduled_history)

        # Baseline growth rate in Bytes per second
        rate_bps = (scheduled_window_bytes / 300.0) if self.scheduled_history else 0.0
        self.window.lblValLogRate.setText(f"{rate_bps:.1f} B/s" if rate_bps > 0 else "0.0 B/s")

        # 4. Projections for 12 hours and 24 hours
        proj_12h_growth = rate_bps * 12 * 3600
        proj_24h_growth = rate_bps * 24 * 3600

        total_12h = curr_log_size + proj_12h_growth
        total_24h = curr_log_size + proj_24h_growth

        if rate_bps > 0:
            self.window.lblValProj12h.setText(
                f"{self._format_size(total_12h)} (+{self._format_size(proj_12h_growth)} growth)"
            )
            self.window.lblValProj24h.setText(
                f"{self._format_size(total_24h)} (+{self._format_size(proj_24h_growth)} growth)"
            )
        else:
            self.window.lblValProj12h.setText(
                f"{self._format_size(curr_log_size)} (steady / awaiting 5m baseline)"
            )
            self.window.lblValProj24h.setText(
                f"{self._format_size(curr_log_size)} (steady / awaiting 5m baseline)"
            )

        # 5. Breakdown of accumulated attribution
        sched_total = self.storage_metrics["scheduled_bytes_accumulated"]
        manual_total = self.storage_metrics["manual_bytes_accumulated"]
        manual_count = self.storage_metrics["manual_checks_count"]
        all_tracked = sched_total + manual_total

        sched_pct = round((sched_total / all_tracked) * 100, 1) if all_tracked > 0 else 100.0

        self.window.lblValScheduledGrowth.setText(
            f"{self._format_size(sched_total)} ({sched_pct}% of tracked activity)"
        )
        self.window.lblValManualGrowth.setText(
            f"{self._format_size(manual_total)} across {manual_count} manual checks"
        )

        # 6. Client transparency report narrative
        explanation = (
            f"Audit transparency breakdown: Automatic schedules have written {self._format_size(sched_total)}, "
            f"operating steadily at ~{rate_bps:.1f} B/s. An administrator performed {manual_count} manual checks, "
            f"which contributed an extra {self._format_size(manual_total)} to storage. "
            f"Projected file sizes (12h: {self._format_size(total_12h)}, 24h: {self._format_size(total_24h)}) "
            f"isolate automatic scheduled polling to guarantee predictable long-term disk planning."
        )
        self.window.lblClientExplanation.setText(explanation)

    def show(self):
        """Sizes and presents the application window maximized on the screen."""
        screen = (self.window.screen() or QApplication.primaryScreen()).availableGeometry()
        self.window.setMinimumSize(screen.width() // 2, screen.height() // 2)
        self.window.showMaximized()

    def _handle_window_close(self, event):
        """
        Called when the user clicks 'X' or closes the window.
        Prevents 'QThread: Destroyed while thread is still running' crashes
        by stopping all timers and waiting for active network workers.
        """
        # 1. Stop all scheduler timers so no new checks start
        self.scheduler.stop_all()

        # 2. Wait for any active scheduled background workers to finish
        for w in list(self.scheduled_workers):
            if w.isRunning():
                w.wait(500)  # Wait up to 500ms for thread to finish

        # 3. Wait for inspector single worker if running
        if self.single_worker is not None and self.single_worker.isRunning():
            self.single_worker.wait(500)

        # 4. Wait for batch worker if running
        if self.worker is not None and self.worker.isRunning():
            self.worker.wait(500)

        # 5. Flush persistent storage metrics to disk
        self._save_storage_metrics()

        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    ui = NetworkMonitorUI("gui.ui")
    ui.show()
    sys.exit(app.exec())