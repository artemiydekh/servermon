import os
import sys
import time
import json
import logging
from pathlib import Path
from collections import deque
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit
import ctypes
from ctypes import wintypes

BASE_DIR = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent

STATUS_COLORS = {
    "ONLINE": "#34d399",
    "OFFLINE": "#f87171",
    "DEGRADED": "#f59e0b",
    "WARNING": "#fbbf24",
    "VERIFYING": "#fbbf24",
    "PENDING": "#64748b",
    "STANDBY": "#94a3b8",
}


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
    QSpinBox, QFrame, QLineEdit, QCheckBox, QTextEdit,
    QScrollArea, QGridLayout
)
from PySide6.QtCore import QFile, QThread, Signal, QStringListModel, Qt, QTimer
from PySide6.QtGui import QTextCursor, QColor
from PySide6.QtUiTools import QUiLoader

# Project internal modules
import storageH
import monitor
import notifier
from notifier import AlertNotifier, parse_recipients
from settings_manager import SettingsManager
from scheduler import ServerScheduler
import gui_charts
import monitor.registry as registry_module

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
        Runs modular checks via monitor.registry and returns the ID and payload.
        """
        mode = self.selected_mode.strip().upper() if self.selected_mode else "SELECTED"
        if mode == "SELECTED":
            enabled = target.get("enabled_checks") or [target.get("check_type", "TCP")]
        elif mode == "ALL":
            enabled = list(registry_module.list_checks())
        else:
            enabled = [mode]

        multi_res = registry_module.run_checks_for_target(
            target=target,
            enabled_checks=enabled,
            timeout=self.timeout
        )
        primary_proto = target.get("check_type", "TCP").upper()
        checks = multi_res.get("checks", {})
        primary_check = checks.get(mode) or checks.get(primary_proto) or (next(iter(checks.values())) if checks else {})
        result = dict(primary_check)
        result["overall_status"] = multi_res.get("overall_status", "ONLINE")
        result["multi_checks"] = checks
        if "response_time_ms" not in result or result.get("response_time_ms") is None:
            result["response_time_ms"] = multi_res.get("primary_latency_ms")
        if "check_type" not in result or not result.get("check_type"):
            result["check_type"] = mode if mode not in ("SELECTED", "ALL") else primary_proto

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
    """Background worker thread that runs modular network verification for a target."""

    check_finished = Signal(dict)

    def __init__(
        self,
        target: dict,
        enabled_checks: Optional[List[str]] = None,
        mode: Optional[str] = None,
        timeout: float = 3.0,
    ):
        super().__init__()
        self.target = target
        if enabled_checks is not None:
            self.enabled_checks = enabled_checks
        elif mode:
            if mode.upper() in ("ALL", "COMPOSITE", "BOTH"):
                self.enabled_checks = target.get("enabled_checks") or list(registry_module.list_checks())
            else:
                self.enabled_checks = [mode.upper()]
        else:
            self.enabled_checks = target.get("enabled_checks") or [target.get("check_type", "TCP")]
        self.mode = mode or "COMPOSITE"
        self.timeout = timeout

    def run(self):
        """Executes all enabled modular checks via monitor.registry and emits composite results."""
        try:
            composite_result = monitor.registry.run_checks_for_target(
                target=self.target,
                enabled_checks=self.enabled_checks,
                timeout=self.timeout,
            )
            composite_result["mode"] = self.mode
            self.check_finished.emit(composite_result)
        except Exception as exc:
            import logging
            logging.getLogger("SingleTargetWorker").exception("SingleTargetWorker execution failed")
            err_payload = {
                "target_id": self.target.get("id"),
                "equipment": self.target.get("name", "Unknown"),
                "host": self.target.get("host", ""),
                "status": "OFFLINE",
                "overall_status": "OFFLINE",
                "error": str(exc),
                "mode": self.mode,
                "checks": {},
            }
            self.check_finished.emit(err_payload)


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
        # MODULAR CONFIGURATION & SETTINGS ENGINE
        # =====================================================================
        self.settings = SettingsManager(filepath="config/settings.json")

        # Read saved user preferences (with fallback to safe defaults)
        self.max_workers = int(self.settings.get("max_workers", 24))
        self.check_timeout = float(self.settings.get("check_timeout", 3.0))
        self.online_interval = int(self.settings.get("online_interval", 60))
        self.offline_interval = int(self.settings.get("offline_interval", 30))
        self.monitor_refresh_ms = int(self.settings.get("monitor_refresh_ms", 2000))
        self.insurance_retries = int(self.settings.get("insurance_retries", 2))
        self.insurance_delay_ms = int(self.settings.get("insurance_delay_ms", 1000))

        # =====================================================================
        # INDEPENDENT SERVER SCHEDULER & ALERT NOTIFIER
        # =====================================================================
        self.scheduler = ServerScheduler()
        self.scheduler.set_intervals(self.online_interval, self.offline_interval)
        self.scheduler.set_insurance_config(self.insurance_retries, self.insurance_delay_ms)
        self.scheduler.check_requested.connect(self._on_scheduled_check)
        self.scheduler.server_down.connect(self._on_server_down_alert)
        self.scheduler.server_recovered.connect(self._on_server_recovered_alert)
        self.scheduler.insurance_attempt.connect(self._on_insurance_attempt)
        self.scheduled_workers = []  # Retains active worker thread references to prevent GC
        self.active_scheduled_target_ids = set()  # Prevents thread piling on slower checks

        # Notification & Alert Coordinator (Desktop Tray + Async Email)
        self.notifier = AlertNotifier(self.window)
        self.notifier.email_dispatched.connect(self._on_email_dispatched)

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
        self.setup_inspector_tabs()
        self.setup_form_multichecks()

        # Server Inspector domain tabs configured in setup_inspector_tabs

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


    def _on_scheduled_check(self, target: dict, check_reason: str = "SCHEDULED"):
        """Handles periodic and insurance retry triggers for scheduled server checks."""
        if not target:
            return
        tid = target.get("id") if isinstance(target, dict) else str(target)
        if tid and tid in self.target_lookup:
            target = self.target_lookup[tid]
        if not isinstance(target, dict):
            return

        # Avoid piling duplicate worker threads if target's previous check is still in-flight
        if tid and tid in self.active_scheduled_target_ids:
            return

        if tid:
            self.active_scheduled_target_ids.add(tid)

        enabled = target.get("enabled_checks") or [target.get("check_type", "TCP")]
        worker = SingleTargetWorker(target=target, enabled_checks=enabled, timeout=self.check_timeout)
        def on_done(payload, t=target, w=worker, r=check_reason, target_id=tid):
            """Processes finished scheduled check and releases worker reference."""
            try:
                self._handle_single_check_finished(payload, t, source=r)
            finally:
                if target_id:
                    self.active_scheduled_target_ids.discard(target_id)
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
        self.window.tblAllServers.itemSelectionChanged.connect(self._sync_selected_table_server)

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
        online_count = sum(1 for t in self.targets if t.get("status") in ("ONLINE", "DEGRADED", "WARNING"))
        offline_count = sum(1 for t in self.targets if t.get("status") in ("OFFLINE", "VERIFYING"))

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

    def _update_tab_enabled_state(self, proto_name: str, enabled: bool):
        """Applies blur effect, shows/hides overlay banner, and updates toggle pill for a check tab."""
        p_cap = proto_name.capitalize()
        container = getattr(self.window, f"container{p_cap}", None)
        banner = getattr(self.window, f"bannerDisabled{p_cap}", None)
        chk = getattr(self.window, f"chk{p_cap}", None)
        badge = getattr(self.window, f"lblBadge{p_cap}", None) or chk

        is_traffic = (proto_name.upper() == "TRAFFIC")
        active_text = "● ACTIVE (WIP)" if is_traffic else "● ACTIVE"
        disabled_text = "○ DISABLED (WIP)" if is_traffic else "○ DISABLED"

        if enabled:
            if container is not None:
                container.setGraphicsEffect(None)
                container.setEnabled(True)
            if banner is not None:
                banner.hide()
            if chk is not None:
                chk.setText(active_text)
                if is_traffic:
                    chk.setStyleSheet(
                        "QCheckBox { font-size: 11px; font-weight: 700; color: #38bdf8; "
                        "background-color: rgba(56, 189, 248, 0.15); border: 1px solid #0284c7; "
                        "border-radius: 6px; padding: 6px 14px; } "
                        "QCheckBox:hover { background-color: rgba(56, 189, 248, 0.25); border: 1px solid #38bdf8; } "
                        "QCheckBox::indicator { width: 0px; height: 0px; }"
                    )
                else:
                    chk.setStyleSheet(
                        "QCheckBox { font-size: 11px; font-weight: 700; color: #10b981; "
                        "background-color: rgba(16, 185, 129, 0.15); border: 1px solid #059669; "
                        "border-radius: 6px; padding: 6px 14px; } "
                        "QCheckBox:hover { background-color: rgba(16, 185, 129, 0.25); border: 1px solid #10b981; } "
                        "QCheckBox::indicator { width: 0px; height: 0px; }"
                    )
            elif badge is not None:
                badge.setText("ACTIVE" if not is_traffic else "WIP / ACTIVE")
        else:
            if container is not None:
                from PySide6.QtWidgets import QGraphicsBlurEffect
                blur = QGraphicsBlurEffect(self.window)
                blur.setBlurRadius(7)
                container.setGraphicsEffect(blur)
                container.setEnabled(False)
            if banner is not None:
                banner.show()
            if chk is not None:
                chk.setText(disabled_text)
                chk.setStyleSheet(
                    "QCheckBox { font-size: 11px; font-weight: 700; color: #64748b; "
                    "background-color: #0f172a; border: 1px solid #334155; "
                    "border-radius: 6px; padding: 6px 14px; } "
                    "QCheckBox:hover { color: #94a3b8; background-color: #1e293b; border: 1px solid #475569; } "
                    "QCheckBox::indicator { width: 0px; height: 0px; }"
                )
            elif badge is not None:
                badge.setText("DISABLED" if not is_traffic else "WIP / OFF")

    def _reset_form_check_configs(self):
        """Resets all modular check parameter fields to default values."""
        if not hasattr(self.window, "tabsFormChecks"):
            return

        # PING
        if hasattr(self.window, "spnFormPingCount"):
            self.window.spnFormPingCount.setValue(4)
        if hasattr(self.window, "spnFormPingTimeout"):
            self.window.spnFormPingTimeout.setValue(1000)

        # TCP
        if hasattr(self.window, "txtFormTcpPorts"):
            self.window.txtFormTcpPorts.clear()
        if hasattr(self.window, "spnFormTcpTimeout"):
            self.window.spnFormTcpTimeout.setValue(3.0)

        # HTTP
        if hasattr(self.window, "txtFormHttpUrl"):
            self.window.txtFormHttpUrl.clear()
        if hasattr(self.window, "cmbFormHttpMethod"):
            self.window.cmbFormHttpMethod.setCurrentText("GET")
        if hasattr(self.window, "spnFormHttpStatus"):
            self.window.spnFormHttpStatus.setValue(200)
        if hasattr(self.window, "chkFormHttpRedirects"):
            self.window.chkFormHttpRedirects.setChecked(True)
        if hasattr(self.window, "spnFormHttpTimeout"):
            self.window.spnFormHttpTimeout.setValue(5.0)

        # HTTPS
        if hasattr(self.window, "txtFormHttpsUrl"):
            self.window.txtFormHttpsUrl.clear()
        if hasattr(self.window, "cmbFormHttpsMethod"):
            self.window.cmbFormHttpsMethod.setCurrentText("GET")
        if hasattr(self.window, "spnFormHttpsStatus"):
            self.window.spnFormHttpsStatus.setValue(200)
        if hasattr(self.window, "chkFormHttpsVerifySsl"):
            self.window.chkFormHttpsVerifySsl.setChecked(True)
        if hasattr(self.window, "chkFormHttpsRedirects"):
            self.window.chkFormHttpsRedirects.setChecked(True)
        if hasattr(self.window, "spnFormHttpsTimeout"):
            self.window.spnFormHttpsTimeout.setValue(5.0)

        # DNS
        if hasattr(self.window, "txtFormDnsDomain"):
            self.window.txtFormDnsDomain.clear()
        if hasattr(self.window, "cmbFormDnsRecordType"):
            self.window.cmbFormDnsRecordType.setCurrentText("A")
        if hasattr(self.window, "txtFormDnsResolvers"):
            self.window.txtFormDnsResolvers.setText("1.1.1.1, 8.8.8.8")
        if hasattr(self.window, "spnFormDnsTimeout"):
            self.window.spnFormDnsTimeout.setValue(3.0)

        # SNMP
        if hasattr(self.window, "spnFormSnmpPort"):
            self.window.spnFormSnmpPort.setValue(161)
        if hasattr(self.window, "txtFormSnmpCommunity"):
            self.window.txtFormSnmpCommunity.setText("public")
        if hasattr(self.window, "cmbFormSnmpVersion"):
            self.window.cmbFormSnmpVersion.setCurrentText("2c")
        if hasattr(self.window, "spnFormSnmpTimeout"):
            self.window.spnFormSnmpTimeout.setValue(3.0)

        # TRAFFIC
        if hasattr(self.window, "txtFormTrafficInterface"):
            self.window.txtFormTrafficInterface.setText("any")
        if hasattr(self.window, "spnFormTrafficDuration"):
            self.window.spnFormTrafficDuration.setValue(3.0)
        if hasattr(self.window, "spnFormTrafficSynThreshold"):
            self.window.spnFormTrafficSynThreshold.setValue(50.0)
        if hasattr(self.window, "spnFormTrafficSweepThreshold"):
            self.window.spnFormTrafficSweepThreshold.setValue(10)
        if hasattr(self.window, "txtFormTrafficTsharkPath"):
            self.window.txtFormTrafficTsharkPath.clear()

    def _populate_form_check_configs(self, target: Dict[str, Any]):
        """Fills modular check parameter inputs from target['check_configs']."""
        if not hasattr(self.window, "tabsFormChecks"):
            return

        self._reset_form_check_configs()
        cfg_all = target.get("check_configs") or {}

        # PING
        cfg_ping = cfg_all.get("PING", {})
        if "count" in cfg_ping and hasattr(self.window, "spnFormPingCount"):
            self.window.spnFormPingCount.setValue(int(cfg_ping["count"]))
        if "timeout_ms" in cfg_ping and hasattr(self.window, "spnFormPingTimeout"):
            self.window.spnFormPingTimeout.setValue(int(cfg_ping["timeout_ms"]))

        # TCP
        cfg_tcp = cfg_all.get("TCP", {})
        if hasattr(self.window, "txtFormTcpPorts"):
            p_val = cfg_tcp.get("ports", "")
            if isinstance(p_val, list):
                p_val = ", ".join(str(p) for p in p_val)
            self.window.txtFormTcpPorts.setText(str(p_val) if p_val else "")
        if "timeout" in cfg_tcp and hasattr(self.window, "spnFormTcpTimeout"):
            self.window.spnFormTcpTimeout.setValue(float(cfg_tcp["timeout"]))

        # HTTP
        cfg_http = cfg_all.get("HTTP", {})
        if hasattr(self.window, "txtFormHttpUrl"):
            self.window.txtFormHttpUrl.setText(str(cfg_http.get("url", "")))
        if "method" in cfg_http and hasattr(self.window, "cmbFormHttpMethod"):
            self.window.cmbFormHttpMethod.setCurrentText(str(cfg_http["method"]).upper())
        if "expected_status" in cfg_http and hasattr(self.window, "spnFormHttpStatus"):
            self.window.spnFormHttpStatus.setValue(int(cfg_http["expected_status"]))
        if "follow_redirects" in cfg_http and hasattr(self.window, "chkFormHttpRedirects"):
            self.window.chkFormHttpRedirects.setChecked(bool(cfg_http["follow_redirects"]))
        if "timeout" in cfg_http and hasattr(self.window, "spnFormHttpTimeout"):
            self.window.spnFormHttpTimeout.setValue(float(cfg_http["timeout"]))

        # HTTPS
        cfg_https = cfg_all.get("HTTPS", {})
        if hasattr(self.window, "txtFormHttpsUrl"):
            self.window.txtFormHttpsUrl.setText(str(cfg_https.get("url", "")))
        if "method" in cfg_https and hasattr(self.window, "cmbFormHttpsMethod"):
            self.window.cmbFormHttpsMethod.setCurrentText(str(cfg_https["method"]).upper())
        if "expected_status" in cfg_https and hasattr(self.window, "spnFormHttpsStatus"):
            self.window.spnFormHttpsStatus.setValue(int(cfg_https["expected_status"]))
        if "verify_ssl" in cfg_https and hasattr(self.window, "chkFormHttpsVerifySsl"):
            self.window.chkFormHttpsVerifySsl.setChecked(bool(cfg_https["verify_ssl"]))
        if "follow_redirects" in cfg_https and hasattr(self.window, "chkFormHttpsRedirects"):
            self.window.chkFormHttpsRedirects.setChecked(bool(cfg_https["follow_redirects"]))
        if "timeout" in cfg_https and hasattr(self.window, "spnFormHttpsTimeout"):
            self.window.spnFormHttpsTimeout.setValue(float(cfg_https["timeout"]))

        # DNS
        cfg_dns = cfg_all.get("DNS", {})
        if hasattr(self.window, "txtFormDnsDomain"):
            self.window.txtFormDnsDomain.setText(str(cfg_dns.get("domain", "") or cfg_dns.get("query_host", "")))
        if "record_type" in cfg_dns and hasattr(self.window, "cmbFormDnsRecordType"):
            self.window.cmbFormDnsRecordType.setCurrentText(str(cfg_dns["record_type"]).upper())
        if hasattr(self.window, "txtFormDnsResolvers"):
            r_val = cfg_dns.get("benchmark_resolvers")
            if isinstance(r_val, list):
                r_val = ", ".join(str(r) for r in r_val)
            self.window.txtFormDnsResolvers.setText(str(r_val) if r_val else "1.1.1.1, 8.8.8.8")
        if "timeout" in cfg_dns and hasattr(self.window, "spnFormDnsTimeout"):
            self.window.spnFormDnsTimeout.setValue(float(cfg_dns["timeout"]))

        # SNMP
        cfg_snmp = cfg_all.get("SNMP", {})
        if hasattr(self.window, "spnFormSnmpPort"):
            snmp_p = cfg_snmp.get("port") or target.get("port") or 161
            self.window.spnFormSnmpPort.setValue(int(snmp_p))
        if hasattr(self.window, "txtFormSnmpCommunity"):
            self.window.txtFormSnmpCommunity.setText(str(cfg_snmp.get("community", "public")))
        if "version" in cfg_snmp and hasattr(self.window, "cmbFormSnmpVersion"):
            self.window.cmbFormSnmpVersion.setCurrentText(str(cfg_snmp["version"]))
        if "timeout" in cfg_snmp and hasattr(self.window, "spnFormSnmpTimeout"):
            self.window.spnFormSnmpTimeout.setValue(float(cfg_snmp["timeout"]))

        # TRAFFIC
        cfg_traffic = cfg_all.get("TRAFFIC", {})
        if hasattr(self.window, "txtFormTrafficInterface"):
            self.window.txtFormTrafficInterface.setText(str(cfg_traffic.get("interface", "any")))
        if "capture_duration_sec" in cfg_traffic and hasattr(self.window, "spnFormTrafficDuration"):
            self.window.spnFormTrafficDuration.setValue(float(cfg_traffic["capture_duration_sec"]))
        if "syn_threshold_pps" in cfg_traffic and hasattr(self.window, "spnFormTrafficSynThreshold"):
            self.window.spnFormTrafficSynThreshold.setValue(float(cfg_traffic["syn_threshold_pps"]))
        if "sweep_threshold_ports" in cfg_traffic and hasattr(self.window, "spnFormTrafficSweepThreshold"):
            self.window.spnFormTrafficSweepThreshold.setValue(int(cfg_traffic["sweep_threshold_ports"]))
        if hasattr(self.window, "txtFormTrafficTsharkPath"):
            self.window.txtFormTrafficTsharkPath.setText(str(cfg_traffic.get("custom_tshark_path", "") or ""))

    def _collect_form_check_configs(self, clean_host: str, port_val: Optional[int], enabled_checks: List[str]) -> Dict[str, Any]:
        """Collects configured parameters from tabsFormChecks for all enabled checks."""
        configs = {}
        if not hasattr(self.window, "tabsFormChecks"):
            return configs

        if "PING" in enabled_checks:
            configs["PING"] = {
                "count": self.window.spnFormPingCount.value() if hasattr(self.window, "spnFormPingCount") else 4,
                "timeout_ms": self.window.spnFormPingTimeout.value() if hasattr(self.window, "spnFormPingTimeout") else 1000,
            }

        if "TCP" in enabled_checks:
            raw_ports = self.window.txtFormTcpPorts.text().strip() if hasattr(self.window, "txtFormTcpPorts") else ""
            configs["TCP"] = {
                "ports": raw_ports if raw_ports else ([port_val] if port_val else [80]),
                "timeout": self.window.spnFormTcpTimeout.value() if hasattr(self.window, "spnFormTcpTimeout") else 3.0,
            }

        if "HTTP" in enabled_checks:
            url_val = self.window.txtFormHttpUrl.text().strip() if hasattr(self.window, "txtFormHttpUrl") else ""
            configs["HTTP"] = {
                "url": url_val if url_val else (f"http://{clean_host}:{port_val}/" if (port_val and port_val != 80) else f"http://{clean_host}/"),
                "method": self.window.cmbFormHttpMethod.currentText() if hasattr(self.window, "cmbFormHttpMethod") else "GET",
                "expected_status": self.window.spnFormHttpStatus.value() if hasattr(self.window, "spnFormHttpStatus") else 200,
                "follow_redirects": self.window.chkFormHttpRedirects.isChecked() if hasattr(self.window, "chkFormHttpRedirects") else True,
                "timeout": self.window.spnFormHttpTimeout.value() if hasattr(self.window, "spnFormHttpTimeout") else 5.0,
            }

        if "HTTPS" in enabled_checks:
            url_val = self.window.txtFormHttpsUrl.text().strip() if hasattr(self.window, "txtFormHttpsUrl") else ""
            configs["HTTPS"] = {
                "url": url_val if url_val else (f"https://{clean_host}:{port_val}/" if (port_val and port_val != 443) else f"https://{clean_host}/"),
                "method": self.window.cmbFormHttpsMethod.currentText() if hasattr(self.window, "cmbFormHttpsMethod") else "GET",
                "expected_status": self.window.spnFormHttpsStatus.value() if hasattr(self.window, "spnFormHttpsStatus") else 200,
                "verify_ssl": self.window.chkFormHttpsVerifySsl.isChecked() if hasattr(self.window, "chkFormHttpsVerifySsl") else True,
                "follow_redirects": self.window.chkFormHttpsRedirects.isChecked() if hasattr(self.window, "chkFormHttpsRedirects") else True,
                "timeout": self.window.spnFormHttpsTimeout.value() if hasattr(self.window, "spnFormHttpsTimeout") else 5.0,
            }

        if "DNS" in enabled_checks:
            dom_val = self.window.txtFormDnsDomain.text().strip() if hasattr(self.window, "txtFormDnsDomain") else ""
            res_str = self.window.txtFormDnsResolvers.text().strip() if hasattr(self.window, "txtFormDnsResolvers") else ""
            resolvers = [r.strip() for r in res_str.split(",") if r.strip()] if res_str else ["1.1.1.1", "8.8.8.8"]
            configs["DNS"] = {
                "domain": dom_val if dom_val else clean_host,
                "record_type": self.window.cmbFormDnsRecordType.currentText() if hasattr(self.window, "cmbFormDnsRecordType") else "A",
                "benchmark_resolvers": resolvers,
                "timeout": self.window.spnFormDnsTimeout.value() if hasattr(self.window, "spnFormDnsTimeout") else 3.0,
            }

        if "SNMP" in enabled_checks:
            configs["SNMP"] = {
                "port": self.window.spnFormSnmpPort.value() if hasattr(self.window, "spnFormSnmpPort") else 161,
                "community": self.window.txtFormSnmpCommunity.text().strip() if hasattr(self.window, "txtFormSnmpCommunity") else "public",
                "version": self.window.cmbFormSnmpVersion.currentText() if hasattr(self.window, "cmbFormSnmpVersion") else "2c",
                "timeout": self.window.spnFormSnmpTimeout.value() if hasattr(self.window, "spnFormSnmpTimeout") else 3.0,
            }

        if "TRAFFIC" in enabled_checks:
            tpath = self.window.txtFormTrafficTsharkPath.text().strip() if hasattr(self.window, "txtFormTrafficTsharkPath") else ""
            configs["TRAFFIC"] = {
                "interface": self.window.txtFormTrafficInterface.text().strip() if hasattr(self.window, "txtFormTrafficInterface") else "any",
                "capture_duration_sec": self.window.spnFormTrafficDuration.value() if hasattr(self.window, "spnFormTrafficDuration") else 3.0,
                "syn_threshold_pps": self.window.spnFormTrafficSynThreshold.value() if hasattr(self.window, "spnFormTrafficSynThreshold") else 50.0,
                "sweep_threshold_ports": self.window.spnFormTrafficSweepThreshold.value() if hasattr(self.window, "spnFormTrafficSweepThreshold") else 10,
                "custom_tshark_path": tpath if tpath else None,
            }

        return configs

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
        if hasattr(self, "chkTcp"):
            for chk in (self.chkPing, self.chkHttp, self.chkHttps, self.chkDns, self.chkSnmp, self.chkTraffic):
                if chk is not None:
                    chk.setChecked(False)
            self.chkTcp.setChecked(True)

        self._reset_form_check_configs()
        for p_name, chk in (
            ("Ping", self.chkPing),
            ("Tcp", self.chkTcp),
            ("Http", self.chkHttp),
            ("Https", self.chkHttps),
            ("Dns", self.chkDns),
            ("Snmp", self.chkSnmp),
            ("Traffic", self.chkTraffic),
        ):
            if chk is not None:
                self._update_tab_enabled_state(p_name, chk.isChecked())

        if hasattr(self.window, "tabsFormChecks"):
            self.window.tabsFormChecks.setDocumentMode(True)
            self.window.tabsFormChecks.setCurrentIndex(1)

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

        enabled_checks = [c.upper() for c in target.get("enabled_checks", [check_type])]
        if hasattr(self, "chkTcp"):
            self.chkPing.setChecked("PING" in enabled_checks)
            self.chkTcp.setChecked("TCP" in enabled_checks)
            self.chkHttp.setChecked("HTTP" in enabled_checks)
            if hasattr(self, "chkHttps") and self.chkHttps is not None:
                self.chkHttps.setChecked("HTTPS" in enabled_checks)
            if hasattr(self, "chkDns") and self.chkDns is not None:
                self.chkDns.setChecked("DNS" in enabled_checks)
            self.chkSnmp.setChecked("SNMP" in enabled_checks)
            self.chkTraffic.setChecked("TRAFFIC" in enabled_checks)

        self._populate_form_check_configs(target)
        for p_name, chk in (
            ("Ping", self.chkPing),
            ("Tcp", self.chkTcp),
            ("Http", self.chkHttp),
            ("Https", self.chkHttps),
            ("Dns", self.chkDns),
            ("Snmp", self.chkSnmp),
            ("Traffic", self.chkTraffic),
        ):
            if chk is not None:
                self._update_tab_enabled_state(p_name, chk.isChecked())

        if hasattr(self.window, "tabsFormChecks"):
            tab_idx = {
                "PING": 0,
                "TCP": 1,
                "HTTP": 2,
                "HTTPS": 3,
                "DNS": 4,
                "SNMP": 5,
                "TRAFFIC": 6,
            }.get(check_type, 1)
            self.window.tabsFormChecks.setCurrentIndex(tab_idx)

        # Switch to Form page (Index 5)
        self.window.stackedWidget.setCurrentIndex(5)
        self.window.txtFormName.setFocus()

    def handle_form_type_change(self, selected_type: str):
        """
        Dynamically adjusts form controls based on selected check type.
        """
        proto = selected_type.strip().upper()
        port_needed = proto in ("TCP", "HTTP", "HTTPS", "DNS", "SNMP")
        self.window.spnFormPort.setEnabled(port_needed)

        # Synchronize corresponding checkbox if available
        if hasattr(self, "chkTcp"):
            mapping = {
                "TCP": self.chkTcp,
                "PING": self.chkPing,
                "HTTP": self.chkHttp,
                "HTTPS": getattr(self, "chkHttps", None),
                "DNS": getattr(self, "chkDns", None),
                "SNMP": self.chkSnmp,
                "TRAFFIC": self.chkTraffic,
            }
            chk_to_check = mapping.get(proto)
            if chk_to_check is not None:
                chk_to_check.setChecked(True)

        # Switch modular tabs to match selected protocol
        tab_idx = {
            "PING": 0,
            "TCP": 1,
            "HTTP": 2,
            "HTTPS": 3,
            "DNS": 4,
            "SNMP": 5,
            "TRAFFIC": 6,
        }.get(proto)
        if tab_idx is not None and hasattr(self.window, "tabsFormChecks"):
            self.window.tabsFormChecks.setCurrentIndex(tab_idx)

        def _set_hint(text):
            if hasattr(self.window, "lblFormPortHint") and self.window.lblFormPortHint is not None:
                self.window.lblFormPortHint.setText(text)

        if proto == "TCP":
            _set_hint("Note: TCP checks test a specific port. For web servers use 80 (HTTP) or 443 (HTTPS).")
        elif proto in ("HTTP", "HTTPS"):
            default_p = 443 if proto == "HTTPS" else 80
            if self.window.spnFormPort.value() in (80, 443, 53, 161):
                self.window.spnFormPort.setValue(default_p)
            _set_hint(f"Note: Web check ({proto}). Standard port is {default_p}.")
        elif proto == "DNS":
            if self.window.spnFormPort.value() in (80, 443, 161):
                self.window.spnFormPort.setValue(53)
            _set_hint("Note: DNS resolution check. Standard port is 53.")
        elif proto == "SNMP":
            if self.window.spnFormPort.value() in (80, 443, 53):
                self.window.spnFormPort.setValue(161)
            _set_hint("Note: SNMP query check. Standard port is 161.")
        elif proto == "TRAFFIC":
            _set_hint("Note: Wireshark packet capture traffic anomaly check (no port needed).")
        elif proto == "PING":
            _set_hint("Note: For Ping (ICMP) checks, port numbers are not applicable.")
        else:
            _set_hint("Note: Port configuration.")

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
        port_needed = check_type in ("TCP", "HTTP", "HTTPS", "DNS", "SNMP")
        if port_needed:
            # Prefer embedded port if typed in host box, otherwise read spinbox
            port_val = embedded_port if embedded_port is not None else int(self.window.spnFormPort.value())
        else:
            port_val = None

        # Step 3: Validate mandatory inputs
        if not raw_name or not clean_host:
            QMessageBox.warning(
                self.window, "Validation Error",
                "Both Equipment Name and Host Address are required to configure a server."
            )
            return

        # Collect enabled checks from checkboxes
        enabled_checks = []
        if hasattr(self, "chkTcp"):
            for proto_name, chk_attr in (
                ("PING", "chkPing"),
                ("TCP", "chkTcp"),
                ("HTTP", "chkHttp"),
                ("HTTPS", "chkHttps"),
                ("DNS", "chkDns"),
                ("SNMP", "chkSnmp"),
                ("TRAFFIC", "chkTraffic"),
            ):
                chk = getattr(self, chk_attr, None)
                if chk is not None and chk.isChecked():
                    enabled_checks.append(proto_name)
        if not enabled_checks:
            enabled_checks = [check_type]

        # Collect modular check parameters
        check_configs = self._collect_form_check_configs(clean_host, port_val, enabled_checks)

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
                    target["error"] = None
                    target["last_checked"] = None
                    target["history"] = {}

                target["host"] = clean_host
                target["check_type"] = check_type
                target["port"] = port_val
                target["enabled_checks"] = enabled_checks
                target["check_configs"] = check_configs

                # Ensure all modern dual-protocol and counter keys exist on the target
                for k, v in storageH.create_target_entry("", "", "").items():
                    target.setdefault(k, v)

                # If this server is currently open in the Inspector, refresh its display
                if self.current_inspected_id is not None and str(self.current_inspected_id) == str(target.get("id")):
                    self.populate_server_detail_page(target["id"])

        else:
            new_entry = storageH.create_target_entry(
                name=raw_name,
                host=clean_host,
                check_type=check_type,
                port=port_val,
                enabled_checks=enabled_checks,
                check_configs=check_configs,
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
            # Stop the scheduler timer and clear any active down alert for the deleted server
            self.scheduler.stop_server_scheduler(selected_id)
            self.notifier.down_servers.pop(selected_id, None)

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
            target_id = table.item(row, 0).data(Qt.UserRole) if table.item(row, 0) else None
            target_obj = self.target_lookup.get(target_id) if target_id else None
            enabled_types = [c.upper() for c in target_obj.get("enabled_checks", [])] if target_obj else []

            matches_type = (
                (type_filter == "ALL TYPES")
                or (type_filter == type_text)
                or (type_filter in type_text)
                or (type_filter in enabled_types)
            )
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
        saved_proto = self.settings.get("default_protocol", "SELECTED")
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

        # Inspector Actions: Run All Checks and Navigation
        self.window.btnDetailBackToServers.clicked.connect(lambda: self.switch_page(1, self.window.btnNavServers))
        self.window.btnDetailRunChecks.clicked.connect(self.run_all_inspector_checks)

        # Domain-specific inspector test triggers
        if hasattr(self.window, "btnTestNetworkLink"):
            self.window.btnTestNetworkLink.clicked.connect(lambda: self.run_domain_inspector_checks(["PING", "TCP"]))
        if hasattr(self.window, "btnTestWebServices"):
            self.window.btnTestWebServices.clicked.connect(lambda: self.run_domain_inspector_checks(["HTTP", "HTTPS", "DNS"]))
        if hasattr(self.window, "btnTestHardware"):
            self.window.btnTestHardware.clicked.connect(lambda: self.run_domain_inspector_checks(["SNMP"]))
        if hasattr(self.window, "btnTestTraffic"):
            self.window.btnTestTraffic.clicked.connect(lambda: self.run_domain_inspector_checks(["TRAFFIC"]))

        # On-Page Direct Check Toggles
        for proto in ("PING", "TCP", "HTTP", "HTTPS", "DNS", "SNMP", "TRAFFIC"):
            chk_w = getattr(self.window, f"chkInsp{proto.capitalize()}", None)
            if chk_w is not None:
                chk_w.toggled.connect(lambda chk, p=proto: self.handle_inspector_toggle(p, chk))

        # CRUD Actions
        self.window.btnAddDevice.clicked.connect(self.open_add_server_form)
        self.window.btnPageAddDevice.clicked.connect(self.open_add_server_form)
        self.window.btnEditDevice.clicked.connect(self.open_edit_server_form)
        self.window.btnDeleteDevice.clicked.connect(self.delete_selected_server)

        # Form Actions
        self.window.btnFormSave.clicked.connect(self.save_server_form)
        self.window.btnFormCancel.clicked.connect(self.cancel_server_form)
        self.window.cmbFormType.currentTextChanged.connect(self.handle_form_type_change)

    def setup_inspector_tabs(self):
        """Initializes vector telemetry graphs inside the domain inspector tabs."""
        self.tabsServerInspector = self.window.tabsServerInspector
        if self.tabsServerInspector is not None:
            self.tabsServerInspector.setDocumentMode(True)
        self.bannerWireshark = self.window.bannerWireshark
        self.lblWiresharkStatus = self.window.lblWiresharkStatus
        self.btnRecheckWireshark = self.window.btnRecheckWireshark
        self.btnRecheckWireshark.clicked.connect(self._recheck_wireshark)

        # Domain action test buttons
        self.btnTestNetworkLink = getattr(self.window, "btnTestNetworkLink", None)
        self.btnTestWebServices = getattr(self.window, "btnTestWebServices", None)
        self.btnTestHardware = getattr(self.window, "btnTestHardware", None)
        self.btnTestTraffic = getattr(self.window, "btnTestTraffic", None)

        # Tab 1: Network Link (Ping & TCP vector graphs)
        self.graph_ping = gui_charts.HistoricalGraphWidget(profile="ping", parent=self.window.boxInspPing)
        self.window.layoutPingGraph.addWidget(self.graph_ping)

        self.graph_tcp = gui_charts.HistoricalGraphWidget(profile="tcp", parent=self.window.boxInspTcp)
        self.window.layoutTcpGraph.addWidget(self.graph_tcp)

        # Tab 2: Web & Services (HTTP vector graph)
        self.graph_http = gui_charts.HistoricalGraphWidget(profile="http", parent=self.window.boxInspHttp)
        self.window.layoutHttpGraph.addWidget(self.graph_http)

        # Tab 3: Host Hardware (SNMP vector graph)
        self.graph_snmp = gui_charts.HistoricalGraphWidget(profile="snmp", parent=self.window.boxInspSnmp)
        self.window.layoutSnmpGraph.addWidget(self.graph_snmp)

        # Tab 4: Traffic & Security (Wireshark PPS vector graph)
        self.graph_traffic = gui_charts.HistoricalGraphWidget(profile="traffic", parent=self.window.boxInspTraffic)
        self.window.layoutTrafficGraph.addWidget(self.graph_traffic)

    def _recheck_wireshark(self):
        """Scans for tshark.exe and updates the missing dependency banner."""
        try:
            import monitor.traffic as tr
            found = tr.discover_tshark()
        except Exception:
            found = None
        if found:
            self.lblWiresharkStatus.setText(f"Wireshark active: {found}")
            self.lblWiresharkStatus.setStyleSheet("color: #34d399; font-weight: 600;")
            self.bannerWireshark.setStyleSheet("background-color: #064e3b; border: 1px solid #059669; border-radius: 8px; padding: 10px;")
            self.btnRecheckWireshark.setText("Active")
            self.btnRecheckWireshark.setEnabled(False)
        else:
            self.lblWiresharkStatus.setText("Wireshark (tshark.exe) not found on system. Install Wireshark and click Re-check.")
            self.lblWiresharkStatus.setStyleSheet("color: #fde68a; font-weight: 600;")
            self.bannerWireshark.setStyleSheet("background-color: #451a03; border: 1px solid #b45309; border-radius: 8px; padding: 10px;")
            self.btnRecheckWireshark.setText("Re-check Wireshark")
            self.btnRecheckWireshark.setEnabled(True)

    def setup_form_multichecks(self):
        """Initializes and wires multi-check selection checkboxes and protocol tabs for pageServerForm."""
        from PySide6.QtWidgets import QHBoxLayout, QCheckBox, QLabel

        # Check if already present on self.window (from modernized gui.ui)
        self.chkPing = getattr(self.window, "chkPing", None)
        self.chkTcp = getattr(self.window, "chkTcp", None)
        self.chkHttp = getattr(self.window, "chkHttp", None)
        self.chkHttps = getattr(self.window, "chkHttps", None)
        self.chkDns = getattr(self.window, "chkDns", None)
        self.chkSnmp = getattr(self.window, "chkSnmp", None)
        self.chkTraffic = getattr(self.window, "chkTraffic", None)

        if self.chkTcp is None:
            # Fallback if running with a legacy UI file without XML checkboxes
            frame_card = getattr(self.window, "frameFormCard", None)
            if frame_card is not None and frame_card.layout() is not None:
                lbl_checks = QLabel("Active Verification Modes:")
                lbl_checks.setStyleSheet("font-weight: 600; color: #f8fafc; margin-top: 8px;")
                box_layout = QHBoxLayout()
                box_layout.setSpacing(14)
                self.chkPing = QCheckBox("Ping")
                self.chkTcp = QCheckBox("TCP")
                self.chkHttp = QCheckBox("HTTP")
                self.chkHttps = QCheckBox("HTTPS")
                self.chkDns = QCheckBox("DNS")
                self.chkSnmp = QCheckBox("SNMP")
                self.chkTraffic = QCheckBox("Traffic")
                for chk in (self.chkPing, self.chkTcp, self.chkHttp, self.chkHttps, self.chkDns, self.chkSnmp, self.chkTraffic):
                    chk.setStyleSheet("color: #e2e8f0; font-weight: 500;")
                    box_layout.addWidget(chk)
                flayout = frame_card.layout()
                idx = max(0, flayout.count() - 2)
                flayout.insertWidget(idx, lbl_checks)
                flayout.insertLayout(idx + 1, box_layout)

        # Apply dark QListView popup to comboboxes so dropdown menu text is never white-on-white
        from PySide6.QtWidgets import QListView
        for cmb in (
            getattr(self.window, "cmbFormType", None),
            getattr(self.window, "cmbHeaderCheckType", None),
            getattr(self.window, "cmbFilterType", None),
            getattr(self.window, "cmbFilterStatus", None),
            getattr(self.window, "cmbFormHttpMethod", None),
            getattr(self.window, "cmbFormHttpsMethod", None),
            getattr(self.window, "cmbFormDnsRecordType", None),
            getattr(self.window, "cmbFormSnmpVersion", None),
        ):
            if cmb is not None:
                cmb.setView(QListView())

        # Wire aliases for backward compatibility with tests/badge lookups
        for p_name in ("Ping", "Tcp", "Http", "Https", "Dns", "Snmp", "Traffic"):
            chk_w = getattr(self.window, f"chk{p_name}", None)
            if chk_w is not None:
                setattr(self.window, f"lblBadge{p_name}", chk_w)

        # Wire checkboxes inside each tab to update blur overlay, status badges, and tab selection
        proto_info = [
            ("Ping", self.chkPing, 0),
            ("Tcp", self.chkTcp, 1),
            ("Http", self.chkHttp, 2),
            ("Https", self.chkHttps, 3),
            ("Dns", self.chkDns, 4),
            ("Snmp", self.chkSnmp, 5),
            ("Traffic", self.chkTraffic, 6),
        ]
        for p_name, chk_widget, tab_idx in proto_info:
            if chk_widget is not None:
                def _make_handler(name, idx):
                    def _on_toggled(checked):
                        self._update_tab_enabled_state(name, checked)
                        if checked and hasattr(self.window, "tabsFormChecks"):
                            self.window.tabsFormChecks.setCurrentIndex(idx)
                    return _on_toggled
                chk_widget.toggled.connect(_make_handler(p_name, tab_idx))

        # Initial refresh of all tab enabled states
        for p_name, chk_widget, _ in proto_info:
            if chk_widget is not None:
                self._update_tab_enabled_state(p_name, chk_widget.isChecked())

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

    def _sync_selected_table_server(self):
        """Synchronizes current_inspected_id with whichever row is selected in the server table."""
        if hasattr(self.window, "stackedWidget") and self.window.stackedWidget.currentIndex() != 1:
            return
        sid = self.get_selected_server_id()
        if sid:
            self.current_inspected_id = sid

    def _open_row_inspector(self, table, row: int):
        """Opens double-clicked row from table in Server Inspector."""
        item = table.item(row, 0)
        if item and item.data(Qt.UserRole):
            target_id = item.data(Qt.UserRole)
            self.current_inspected_id = target_id
            self.populate_server_detail_page(target_id)
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

        # Modular Telemetry (Extracted dynamically from rolling telemetry history)
        history = target.get("history", {})
        enabled = [c.upper() for c in target.get("enabled_checks", [target.get("check_type", "TCP")])]

        if len(enabled) == 1:
            proto = enabled[0]
            samples = history.get(proto, [])
            latest = samples[-1] if samples else None
            lat = latest.get("latency_ms") or latest.get("response_time_ms") if latest else None
            st = latest.get("status", "Standby") if latest else "Standby"
            lat_display = f"{lat} ms" if lat is not None else "-- ms"
            self.window.lblInfoIcmp.setText(f"{proto} Check: {lat_display} ({st})")
            self.window.lblInfoTcp.setText(f"Mode: Single Check ({proto})")
        elif len(enabled) == 2:
            p1, p2 = enabled[0], enabled[1]
            s1 = history.get(p1, [])
            l1 = s1[-1] if s1 else None
            lat1 = l1.get("latency_ms") or l1.get("response_time_ms") if l1 else None
            st1 = l1.get("status", "Standby") if l1 else "Standby"
            lat1_disp = f"{lat1} ms" if lat1 is not None else "-- ms"

            s2 = history.get(p2, [])
            l2 = s2[-1] if s2 else None
            lat2 = l2.get("latency_ms") or l2.get("response_time_ms") if l2 else None
            st2 = l2.get("status", "Standby") if l2 else "Standby"
            lat2_disp = f"{lat2} ms" if lat2 is not None else "-- ms"

            self.window.lblInfoIcmp.setText(f"{p1}: {lat1_disp} ({st1})")
            self.window.lblInfoTcp.setText(f"{p2}: {lat2_disp} ({st2})")
        else:
            primary_p = target.get("check_type", enabled[0]).upper() if enabled else "TCP"
            p_samples = history.get(primary_p, [])
            latest_p = p_samples[-1] if p_samples else None
            lat_p = latest_p.get("latency_ms") or latest_p.get("response_time_ms") if latest_p else None
            st_p = latest_p.get("status", "Standby") if latest_p else "Standby"
            lat_p_disp = f"{lat_p} ms" if lat_p is not None else "-- ms"
            self.window.lblInfoIcmp.setText(f"{primary_p} (Primary): {lat_p_disp} ({st_p})")
            self.window.lblInfoTcp.setText(f"Active Checks: {', '.join(enabled)}")

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
        self.run_all_inspector_checks()

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
        Populates pageServerDetail with modular domain telemetry (Network Link,
        Web & Services, Host Hardware, Traffic & Security) and historical vector graphs.
        """
        target = self.target_lookup.get(target_id)
        if not target:
            return

        self.current_inspected_id = target_id

        # Headers & Identifiers
        self.window.lblDetServerName.setText(target.get("name", "Unknown Server"))
        self.window.lblDetServerHost.setText(f"Host: {target.get('host')} | ID: {target.get('id')}")

        # Overall Status Badge
        status = target.get("status", "READY")
        self.window.lblDetStatusBadge.setText(status)
        badge_styles = {
            "ONLINE": "background-color: #064e3b; color: #34d399; font-weight: 700; padding: 6px 16px; border-radius: 8px;",
            "DEGRADED": "background-color: #78350f; color: #fde047; font-weight: 700; padding: 6px 16px; border-radius: 8px;",
            "WARNING": "background-color: #7c2d12; color: #fdba74; font-weight: 700; padding: 6px 16px; border-radius: 8px;",
            "VERIFYING": "background-color: #1e3a8a; color: #93c5fd; font-weight: 700; padding: 6px 16px; border-radius: 8px;",
            "OFFLINE": "background-color: #7f1d1d; color: #f87171; font-weight: 700; padding: 6px 16px; border-radius: 8px;",
        }
        self.window.lblDetStatusBadge.setStyleSheet(
            badge_styles.get(status, "background-color: #1e293b; color: #94a3b8; font-weight: 700; padding: 6px 16px; border-radius: 8px;")
        )

        # Sync Header Check Mode Toggles without triggering handlers
        enabled = target.get("enabled_checks", ["TCP"])
        enabled_upper = [c.upper() for c in enabled] if isinstance(enabled, list) else ["TCP"]

        self._suppress_insp_toggles = True
        for proto in ("PING", "TCP", "HTTP", "HTTPS", "DNS", "SNMP", "TRAFFIC"):
            chk_w = getattr(self.window, f"chkInsp{proto.capitalize()}", None)
            if chk_w is not None:
                chk_w.setChecked(proto in enabled_upper)
        self._suppress_insp_toggles = False

        # 4 Unified Metric Overview Cards
        last_lat = target.get("response_time_ms")
        self.window.lblValDetLat.setText(f"{last_lat} ms" if last_lat is not None else "-- ms")

        avg_lat = target.get("avg_response_time_ms")
        self.window.lblValDetAvgLat.setText(f"{avg_lat} ms" if avg_lat is not None else "-- ms")

        succ = target.get("successes", 0)
        fail = target.get("failures", 0)
        total = succ + fail
        uptime_pct = round((succ / total) * 100, 1) if total > 0 else 100.0
        self.window.lblValDetUptime.setText(f"{uptime_pct}%")

        self.window.lblValDetTotalChecks.setText(f"{succ} OK / {fail} Fail")

        # Diagnostics Meta Bar
        self.window.lblDetSpecLast.setText(f"Last check: {target.get('last_checked') or 'Never'}")
        err = target.get("error")
        if err:
            self.window.lblDetSpecError.setText(err)
            self.window.lblDetSpecError.setStyleSheet("color: #ef4444; font-weight: 500; font-size: 11px;")
        else:
            self.window.lblDetSpecError.setText("None - System Operating Normally")
            self.window.lblDetSpecError.setStyleSheet("color: #10b981; font-weight: 500; font-size: 11px;")

        # Domain Tabs Accessibility & Status Labels
        if hasattr(self, "tabsServerInspector") and self.tabsServerInspector is not None:
            for tab_idx in range(self.tabsServerInspector.count()):
                self.tabsServerInspector.setTabVisible(tab_idx, True)
            has_net = "PING" in enabled_upper or "TCP" in enabled_upper
            has_web = "HTTP" in enabled_upper or "HTTPS" in enabled_upper or "DNS" in enabled_upper
            has_snmp = "SNMP" in enabled_upper
            has_traffic = "TRAFFIC" in enabled_upper
            self.tabsServerInspector.setTabText(0, "Network Link" if has_net else "Network Link (Standby)")
            self.tabsServerInspector.setTabText(1, "Web and Services" if has_web else "Web and Services (Standby)")
            self.tabsServerInspector.setTabText(2, "Host Hardware" if has_snmp else "Host Hardware (Standby)")
            self.tabsServerInspector.setTabText(3, "Traffic and Security" if has_traffic else "Traffic and Security (Standby)")

        # Ingest Telemetry History into Domain Tabs
        history = target.get("history", {})

        # TAB 1: Network Link (Ping & TCP)
        ping_history = history.get("PING", [])
        if hasattr(self, "graph_ping"):
            self.graph_ping.set_data(ping_history)
            self.graph_ping.repaint()
        latest_ping = ping_history[-1] if ping_history else None
        p_lat = latest_ping.get("latency_ms") or latest_ping.get("response_time_ms") if latest_ping else None
        self.window.lblValDetIcmpLat.setText(f"Last: {p_lat} ms" if p_lat is not None else "Last: -- ms")
        self.window.lblDetSpecResolved.setText(f"Resolved: {target.get('resolved_ip') or 'Unresolved'}")
        p_drops = sum(1 for s in ping_history if s.get("status") == "OFFLINE")
        p_loss = round((p_drops / len(ping_history)) * 100, 1) if ping_history else 0.0
        self.window.lblPingLossRate.setText(f"Drop: {p_loss}%")

        tcp_history = history.get("TCP", [])
        if hasattr(self, "graph_tcp"):
            self.graph_tcp.set_data(tcp_history)
            self.graph_tcp.repaint()
        latest_tcp = tcp_history[-1] if tcp_history else None
        t_lat = latest_tcp.get("latency_ms") or latest_tcp.get("response_time_ms") if latest_tcp else None
        self.window.lblValDetTcpLat.setText(f"Handshake: {t_lat} ms" if t_lat is not None else "Handshake: -- ms")
        self.window.lblDetSpecPort.setText(f"Port: {target.get('port') or 'N/A'}")
        t_stat = latest_tcp.get("status", "STANDBY") if latest_tcp else "STANDBY"
        self.window.lblDetTcpResult.setText(f"Status: {t_stat}")

        # TAB 2: Web & Services (HTTP, SSL, DNS)
        http_history = sorted(history.get("HTTP", []) + history.get("HTTPS", []), key=lambda x: x.get("timestamp", "")) if ("HTTP" in history and "HTTPS" in history) else (history.get("HTTP") or history.get("HTTPS") or [])
        if hasattr(self, "graph_http"):
            self.graph_http.set_data(http_history)
            self.graph_http.repaint()
        latest_http = http_history[-1] if http_history else None
        h_lat = latest_http.get("latency_ms") or latest_http.get("response_time_ms") if latest_http else None
        self.window.lblValDetHttpLat.setText(f"Duration: {h_lat} ms" if h_lat is not None else "Duration: -- ms")
        code = latest_http.get("status_code") if latest_http else None
        self.window.lblHttpStatus.setText(f"Status: {code} OK" if code == 200 else (f"Status: {code}" if code else ("Status: OFFLINE" if latest_http and latest_http.get("status") == "OFFLINE" else "Status: --")))
        url_str = (latest_http.get("url") or latest_http.get("final_url")) if latest_http else target.get("host")
        self.window.lblHttpUrl.setText(f"URL: {url_str or '--'}")
        if hasattr(self.window, "lblHttpRedirects"):
            self.window.lblHttpRedirects.setText(f"Redirects: {latest_http.get('redirect_count', 0) if latest_http else 0}")

        ssl_info = (latest_http.get("ssl") or latest_http.get("ssl_audit")) if latest_http and isinstance(latest_http.get("ssl") or latest_http.get("ssl_audit"), dict) else {}
        if not ssl_info and "HTTPS" in history and history["HTTPS"]:
            latest_https = history["HTTPS"][-1]
            if isinstance(latest_https, dict):
                ssl_info = (latest_https.get("ssl") or latest_https.get("ssl_audit")) if isinstance(latest_https.get("ssl") or latest_https.get("ssl_audit"), dict) else {}
        if ssl_info:
            self.window.lblSslIssuer.setText(f"Issuer: {ssl_info.get('issuer', 'Unknown')}")
            days = ssl_info.get("days_remaining")
            exp_str = f"in {days} days (Valid)" if days is not None and days > 0 else ("Expired" if ssl_info.get("is_expired") else "Invalid / Not verified")
            self.window.lblSslExpiry.setText(f"Expiration: {exp_str}")
        else:
            self.window.lblSslIssuer.setText("Issuer: N/A (Plain HTTP / Not Checked)")
            self.window.lblSslExpiry.setText("Expiration: N/A")

        dns_history = history.get("DNS", [])
        latest_dns = dns_history[-1] if dns_history else None
        if latest_dns:
            sys_lat = latest_dns.get("system_dns_latency_ms")
            if sys_lat is None:
                sys_lat = latest_dns.get("latency_ms") or latest_dns.get("response_time_ms")
            bench_lat = latest_dns.get("benchmark_dns_latency_ms")
            if bench_lat is None and isinstance(latest_dns.get("benchmark_latencies_ms"), dict):
                bench_lat = latest_dns["benchmark_latencies_ms"].get("1.1.1.1") or (next(iter(latest_dns["benchmark_latencies_ms"].values())) if latest_dns["benchmark_latencies_ms"] else None)
            delta = latest_dns.get("latency_delta_ms")
            self.window.lblDnsPrimary.setText(f"System DNS: {sys_lat if sys_lat is not None else '--'} ms")
            self.window.lblDnsBenchmark.setText(f"Benchmark (1.1.1.1): {bench_lat if bench_lat is not None else '--'} ms")
            self.window.lblDnsDelta.setText(f"Delta: {delta if delta is not None else '--'} ms")
        else:
            self.window.lblDnsPrimary.setText("System DNS: -- ms")
            self.window.lblDnsBenchmark.setText("Benchmark (1.1.1.1): -- ms")
            self.window.lblDnsDelta.setText("Delta: -- ms")

        # TAB 3: Host Hardware (SNMP Telemetry)
        snmp_history = history.get("SNMP", [])
        if hasattr(self, "graph_snmp"):
            self.graph_snmp.set_data(snmp_history)
            self.graph_snmp.repaint()
        latest_snmp = snmp_history[-1] if snmp_history else None
        if latest_snmp:
            cpu_val = latest_snmp.get("cpu_load_pct")
            ram_val = latest_snmp.get("ram_usage_pct")
            disk_val = latest_snmp.get("disk_usage_pct")

            if cpu_val is not None:
                cpu = int(cpu_val)
                self.window.barSlotCPU.setValue(cpu)
                self.window.lblValSlotCPU.setText(f"{cpu}%")
                self.window.lblValSlotCPU.setToolTip(f"CPU Load: {cpu}%")
            else:
                self.window.barSlotCPU.setValue(0)
                self.window.lblValSlotCPU.setText("N/A")
                self.window.lblValSlotCPU.setToolTip("Telemetry not provided by this SNMP agent")

            if ram_val is not None:
                ram = int(ram_val)
                self.window.barSlotMemory.setValue(ram)
                self.window.lblValSlotMemory.setText(f"{ram}%")
                self.window.lblValSlotMemory.setToolTip(f"RAM Usage: {ram}%")
            else:
                self.window.barSlotMemory.setValue(0)
                self.window.lblValSlotMemory.setText("N/A")
                self.window.lblValSlotMemory.setToolTip("Telemetry not provided by this SNMP agent")

            if disk_val is not None:
                disk = int(disk_val)
                self.window.barSlotDisk.setValue(disk)
                self.window.lblValSlotDisk.setText(f"{disk}%")
                self.window.lblValSlotDisk.setToolTip(f"Disk Usage: {disk}%")
            else:
                self.window.barSlotDisk.setValue(0)
                self.window.lblValSlotDisk.setText("N/A")
                self.window.lblValSlotDisk.setToolTip("Telemetry not provided by this SNMP agent")

            uptime = latest_snmp.get("sys_uptime") or ("Offline" if latest_snmp.get("status") == "OFFLINE" else "--")
            self.window.lblSnmpSysUptime.setText(f"Uptime: {uptime}")
            descr = latest_snmp.get("sys_descr")
            if not descr and latest_snmp.get("error"):
                descr = f"Offline: {latest_snmp['error']}"
            self.window.lblSnmpSysDescr.setText(f"System: {descr or '--'}")
        else:
            self.window.barSlotCPU.setValue(0)
            self.window.lblValSlotCPU.setText("N/A")
            self.window.barSlotMemory.setValue(0)
            self.window.lblValSlotMemory.setText("N/A")
            self.window.barSlotDisk.setValue(0)
            self.window.lblValSlotDisk.setText("N/A")
            self.window.lblSnmpSysUptime.setText("Uptime: --")
            self.window.lblSnmpSysDescr.setText("System: --")

        # TAB 4: Traffic & Security (Wireshark Anomaly)
        self._recheck_wireshark()
        traffic_history = history.get("TRAFFIC", [])
        if hasattr(self, "graph_traffic"):
            self.graph_traffic.set_data(traffic_history)
            self.graph_traffic.repaint()
        latest_traffic = traffic_history[-1] if traffic_history else None
        if latest_traffic:
            pps = latest_traffic.get("packet_rate_pps")
            if pps is None:
                pps = latest_traffic.get("pps", 0)
            peak = latest_traffic.get("peak_pps", pps)
            self.window.lblTrafficPPS.setText(f"{pps} PPS (Peak: {peak} PPS)")
            threat = latest_traffic.get("threat_level", "NORMAL")
            threat_styles = {
                "NORMAL": "background-color: #064e3b; color: #34d399; font-weight: 700; padding: 4px 12px; border-radius: 6px;",
                "SUSPICIOUS": "background-color: #78350f; color: #fde047; font-weight: 700; padding: 4px 12px; border-radius: 6px;",
                "ATTACK WARNING": "background-color: #7f1d1d; color: #f87171; font-weight: 700; padding: 4px 12px; border-radius: 6px;",
            }
            self.window.lblThreatBadge.setText(f"SECURITY: {threat}")
            self.window.lblThreatBadge.setStyleSheet(threat_styles.get(threat, threat_styles["NORMAL"]))
            heur = latest_traffic.get("threat_reasons") or latest_traffic.get("heuristic_triggers", [])
            if heur:
                heur_txt = f"Alert: {', '.join(heur)}"
            elif latest_traffic.get("status") == "OFFLINE" and latest_traffic.get("error"):
                heur_txt = f"Offline: {latest_traffic['error']}"
            else:
                heur_txt = "Heuristics: Normal packet flow. No SYN flood or port sweep detected."
            self.window.lblThreatDetails.setText(heur_txt)
        else:
            self.window.lblTrafficPPS.setText("0 PPS (Peak: 0 PPS)")
            self.window.lblThreatBadge.setText("SECURITY: STANDBY")
            self.window.lblThreatDetails.setText("Heuristics: Standby. Run verification to inspect network traffic.")

    def handle_inspector_toggle(self, check_type: str, checked: bool):
        """
        Triggered when operator clicks an on-page protocol toggle checkbox in Inspector.
        Immediately updates target['enabled_checks'], persists changes, and refreshes UI.
        """
        if getattr(self, "_suppress_insp_toggles", False):
            return
        target = self._ensure_active_inspected_target()
        if not target:
            return

        enabled = list(target.get("enabled_checks", []))
        norm_type = check_type.strip().upper()

        if checked and norm_type not in enabled:
            enabled.append(norm_type)
        elif not checked and norm_type in enabled:
            if len(enabled) <= 1:
                # Disallow disabling the final active check
                self._suppress_insp_toggles = True
                chk_w = getattr(self.window, f"chkInsp{check_type.capitalize()}", None)
                if chk_w is not None:
                    chk_w.setChecked(True)
                self._suppress_insp_toggles = False
                return
            enabled.remove(norm_type)

        target["enabled_checks"] = enabled
        self.schedule_disk_save()
        self.populate_server_detail_page(target.get("id"))
        if checked:
            self.run_domain_inspector_checks([norm_type])

    def _ensure_active_inspected_target(self) -> dict:
        """Helper ensuring self.current_inspected_id points to a valid target."""
        if self.current_inspected_id and self.current_inspected_id in self.target_lookup:
            return self.target_lookup[self.current_inspected_id]
        selected_row_id = self.get_selected_server_id()
        if selected_row_id and selected_row_id in self.target_lookup:
            self.current_inspected_id = selected_row_id
            return self.target_lookup[self.current_inspected_id]
        if self.targets:
            self.current_inspected_id = self.targets[0]["id"]
            return self.target_lookup.get(self.current_inspected_id)
        return None

    def run_all_inspector_checks(self):
        """
        Triggered by 'Run All Checks' inspector button.
        Executes all active verification checks concurrently on a background worker thread.
        """
        if self.single_worker is not None and self.single_worker.isRunning():
            return

        target = self._ensure_active_inspected_target()
        if not target:
            return

        for btn_name in ("btnDetailRunChecks", "btnTestNetworkLink", "btnTestWebServices", "btnTestHardware", "btnTestTraffic"):
            btn = getattr(self.window, btn_name, None)
            if btn is not None:
                btn.setEnabled(False)

        self.window.lblDetStatusBadge.setText("CHECKING")
        self.window.lblDetStatusBadge.setStyleSheet(
            "background-color: #1e293b; color: #38bdf8; font-weight: 700; padding: 6px 16px; border-radius: 8px;"
        )

        enabled = target.get("enabled_checks")
        self.single_worker = SingleTargetWorker(
            target=target,
            enabled_checks=enabled,
            timeout=self.check_timeout,
        )
        self.single_worker.check_finished.connect(
            lambda payload, t=target: self._handle_single_check_finished(payload, t)
        )
        self.single_worker.start()

    def run_domain_inspector_checks(self, domain_checks: List[str]):
        """
        Executes dedicated checks for a specific inspector subtab domain
        (Network Link, Web Services, Host Hardware, or Traffic & Security).
        """
        if self.single_worker is not None and self.single_worker.isRunning():
            return

        target = self._ensure_active_inspected_target()
        if not target:
            return

        target_enabled = target.get("enabled_checks") or []
        checks_to_run = list(domain_checks)
        if "HTTP" in checks_to_run and "HTTPS" in checks_to_run:
            if "HTTPS" in target_enabled and "HTTP" not in target_enabled:
                checks_to_run.remove("HTTP")
            elif "HTTP" in target_enabled and "HTTPS" not in target_enabled:
                checks_to_run.remove("HTTPS")

        for btn_name in ("btnDetailRunChecks", "btnTestNetworkLink", "btnTestWebServices", "btnTestHardware", "btnTestTraffic"):
            btn = getattr(self.window, btn_name, None)
            if btn is not None:
                btn.setEnabled(False)

        self.window.lblDetStatusBadge.setText("CHECKING")
        self.window.lblDetStatusBadge.setStyleSheet(
            "background-color: #1e293b; color: #38bdf8; font-weight: 700; padding: 6px 16px; border-radius: 8px;"
        )

        self.single_worker = SingleTargetWorker(
            target=target,
            enabled_checks=checks_to_run,
            timeout=self.check_timeout,
        )
        self.single_worker.check_finished.connect(
            lambda payload, t=target: self._handle_single_check_finished(payload, t, source="DOMAIN")
        )
        self.single_worker.start()

    def _handle_single_check_finished(self, payload: dict, target: dict, source: str = "MANUAL"):
        """
        Main-thread handler for SingleTargetWorker.check_finished signal.
        Ingests composite results, updates targets, appends rolling history, and refreshes UI.
        """
        for btn_name in ("btnDetailRunChecks", "btnTestNetworkLink", "btnTestWebServices", "btnTestHardware", "btnTestTraffic"):
            btn = getattr(self.window, btn_name, None)
            if btn is not None:
                btn.setEnabled(True)

        target_id = (target.get("id") if isinstance(target, dict) else None) or payload.get("target_id")
        if target_id and target_id in self.target_lookup:
            canonical = self.target_lookup[target_id]
            if isinstance(target, dict) and canonical is not target:
                for k, v in target.items():
                    if k not in canonical:
                        canonical[k] = v
            target = canonical
        elif not isinstance(target, dict):
            return

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        checks = payload.get("checks") or payload.get("multi_checks") or {}
        if not checks and payload.get("check_type"):
            checks = {payload["check_type"]: payload}

        for proto, res in checks.items():
            if not isinstance(res, dict):
                continue
            if res.get("resolved_ip"):
                target["resolved_ip"] = res["resolved_ip"]
            if not res.get("timestamp"):
                res["timestamp"] = now
            storageH.append_telemetry_sample(target, proto, res)
            self._log_and_append_result(target, proto, res)

        overall_status = payload.get("overall_status", "UNKNOWN")
        primary_latency = payload.get("primary_latency_ms")

        # Determine whether this run evaluated all enabled checks for the target
        target_enabled = target.get("enabled_checks") or [target.get("check_type", "TCP")]
        all_enabled_run = all(c in checks for c in target_enabled)

        if all_enabled_run or source != "DOMAIN":
            if target.get("id"):
                eval_dict = {
                    "status": overall_status if overall_status in ("ONLINE", "OFFLINE") else ("ONLINE" if overall_status in ("DEGRADED", "WARNING") else "OFFLINE"),
                    "response_time_ms": primary_latency,
                    "error": None,
                }
                outcome = self.scheduler.handle_check_result(target, eval_dict)
                if outcome == "INSURANCE_CHECKING":
                    target["status"] = "VERIFYING"
                elif outcome in ("CONFIRMED_DOWN", "STILL_OFFLINE"):
                    target["status"] = "OFFLINE"
                else:
                    target["status"] = overall_status
            else:
                target["status"] = overall_status

            target["response_time_ms"] = primary_latency
            # Update math counters
            self._update_target_counters(target, target["status"], primary_latency)
        else:
            # Domain-specific test: record domain latency if target has none yet, and don't trip offline alarms
            if target.get("response_time_ms") is None and primary_latency is not None:
                target["response_time_ms"] = primary_latency
            if target.get("status") in ("PENDING", "UNKNOWN") and overall_status in ("ONLINE", "DEGRADED", "WARNING"):
                target["status"] = overall_status
            # Update math counters for domain verification checks
            self._update_target_counters(target, overall_status, primary_latency)

        target["last_checked"] = now

        # Refresh all views and persist
        self._refresh_target_ui(target)
        self.record_log_growth(source=source)

    def _update_target_counters(self, target: dict, status: str, latency: float, check_mode: str = "TCP"):
        """Helper to increment general target counters."""
        is_online = (status in ("ONLINE", "DEGRADED", "WARNING"))
        if is_online:
            target["successes"] = target.get("successes", 0) + 1
            if latency is not None:
                tot = target.get("total_response_time_ms", 0.0) + latency
                target["total_response_time_ms"] = tot
                target["avg_response_time_ms"] = round(tot / target["successes"], 2)
        else:
            target["failures"] = target.get("failures", 0) + 1

    def _log_and_append_result(self, target: dict, mode: str, res: dict):
        """Appends audit record directly into the live Audit Logs console."""
        log_line = res.get("log_entry")
        if not log_line:
            check_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            equipment = target.get("name", "Unknown") if target else "Unknown"
            host_str = target.get("host", "Unknown") if target else "Unknown"
            resolved_ip = res.get("resolved_ip") or "Unresolved"
            check_type = res.get("check_type") or mode
            proto_upper = str(check_type).upper()
            if res.get("port") is not None:
                port = res["port"]
            elif proto_upper in ("TCP", "HTTP", "HTTPS", "DNS", "SNMP"):
                port = target.get("port") if target and target.get("port") is not None else {"TCP": 80, "HTTP": 80, "HTTPS": 443, "DNS": 53, "SNMP": 161}.get(proto_upper, "N/A")
            else:
                port = "N/A"
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

    def _refresh_target_ui(self, target: dict):
        """Commits target state changes to disk and updates all attached UI views."""
        self.schedule_disk_save()
        self.update_single_server_row_in_place(target)
        self.update_dashboard_stat_cards()

        tid = target.get("id")
        # Update Inspector if viewing this target
        if self.current_inspected_id is not None and str(self.current_inspected_id) == str(tid):
            self.populate_server_detail_page(tid)

        # Update header auto-refresh indicator
        now_time = datetime.now().strftime("%H:%M:%S")
        if hasattr(self.window, "lblLastCheckedHeader"):
            self.window.lblLastCheckedHeader.setText(f"Last check: {now_time} (Auto-refresh: {self.online_interval}s)")

        # Update Recent Servers list
        if target in self.recent_targets:
            self.recent_targets.remove(target)
        self.recent_targets.insert(0, target)
        self.populate_recent_servers_table()

        # Sync dashboard quick inspector view if matching
        selected_quick_id = self.window.cmbQuickTarget.currentData()
        if tid is not None and str(tid) == str(selected_quick_id):
            self.update_dashboard_quick_target_card(tid)

    def _recompute_delta_and_update(self, target: dict):
        """Clean forwarder to _refresh_target_ui."""
        self._refresh_target_ui(target)


    # =========================================================================
    # SETTINGS PAGE & WORKER CONCURRENCY CONFIGURATION
    # =========================================================================

    def setup_settings_page(self):
        """
        Constructs the configuration cards within Page 4 (Application Settings).
        Includes thread worker count selection, socket verification timeout controls,
        scheduler intervals, insurance checks configuration, and full SMTP email alert setup.
        """
        layout = self.window.p4_layout

        # =====================================================================
        # CARD 1: Performance, Concurrency & Cadence Settings
        # =====================================================================
        frame_settings = QFrame()
        frame_settings.setStyleSheet(
            "background-color: #131d33; border: 1px solid #1e293b; border-radius: 12px; padding: 20px;"
        )
        frame_layout = QVBoxLayout(frame_settings)
        frame_layout.setSpacing(16)

        # Title
        lbl_perf_header = QLabel("Performance & Verification Cadence")
        lbl_perf_header.setStyleSheet("font-size: 16px; font-weight: 700; color: #ffffff;")
        frame_layout.addWidget(lbl_perf_header)

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
        lbl_timeout_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff; margin-top: 6px;")
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
        lbl_intervals_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff; margin-top: 6px;")
        frame_layout.addWidget(lbl_intervals_title)

        intervals_row = QHBoxLayout()
        col_online = QVBoxLayout()
        col_online.addWidget(QLabel("Online Server Interval (Sec):"))
        self.spn_online_interval = QSpinBox()
        self.spn_online_interval.setRange(5, 3600)
        self.spn_online_interval.setValue(self.online_interval)
        self.spn_online_interval.setStyleSheet("background-color: #1e293b; border: 1px solid #334155; padding: 6px 12px; font-weight: 600; border-radius: 6px;")
        self.spn_online_interval.valueChanged.connect(self.handle_interval_change)
        col_online.addWidget(self.spn_online_interval)
        intervals_row.addLayout(col_online)

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

        # Setting 4: Subsequent Insurance Checks on Failure
        lbl_insurance_title = QLabel("Subsequent Insurance Checks on Failure:")
        lbl_insurance_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff; margin-top: 6px;")
        frame_layout.addWidget(lbl_insurance_title)

        insurance_row = QHBoxLayout()
        lbl_insurance_desc = QLabel("Immediate confirmation checks before declaring server down & firing alerts:")
        lbl_insurance_desc.setStyleSheet("color: #94a3b8; font-size: 12px;")
        self.spn_insurance_retries = QSpinBox()
        self.spn_insurance_retries.setRange(0, 5)
        self.spn_insurance_retries.setValue(self.insurance_retries)
        self.spn_insurance_retries.setToolTip("0 = Alert on first failure, 2 = Check 2 additional times before alerting (recommended)")
        self.spn_insurance_retries.setStyleSheet("background-color: #1e293b; border: 1px solid #334155; padding: 6px 12px; font-weight: 600; border-radius: 6px;")
        self.spn_insurance_retries.valueChanged.connect(self.handle_insurance_retries_change)
        insurance_row.addWidget(lbl_insurance_desc)
        insurance_row.addStretch()
        insurance_row.addWidget(self.spn_insurance_retries)
        frame_layout.addLayout(insurance_row)

        # Setting 5: Resource Monitor Refresh Rate
        lbl_monitor_speed_title = QLabel("App Resource Monitor Speed / Refresh Rate:")
        lbl_monitor_speed_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff; margin-top: 6px;")
        frame_layout.addWidget(lbl_monitor_speed_title)

        self.cmb_monitor_speed = QComboBox()
        self.cmb_monitor_speed.addItem("Fast / High Fidelity (500ms)", 500)
        self.cmb_monitor_speed.addItem("Rapid (1000ms / 1 Second)", 1000)
        self.cmb_monitor_speed.addItem("Normal Default (2000ms / 2 Seconds)", 2000)
        self.cmb_monitor_speed.addItem("Low Power / Minimal (5000ms / 5 Seconds)", 5000)
        self.cmb_monitor_speed.setStyleSheet(
            "background-color: #1e293b; border: 1px solid #334155; padding: 8px 12px; font-weight: 600; border-radius: 6px;"
        )
        idx = self.cmb_monitor_speed.findData(self.monitor_refresh_ms)
        self.cmb_monitor_speed.setCurrentIndex(max(0, idx))
        self.cmb_monitor_speed.currentIndexChanged.connect(self.handle_monitor_speed_change)
        frame_layout.addWidget(self.cmb_monitor_speed)

        # =====================================================================
        # CARD 2: Email & Server Down Alert Notifications
        # =====================================================================
        frame_email = QFrame()
        frame_email.setStyleSheet(
            "background-color: #131d33; border: 1px solid #1e293b; border-radius: 12px; padding: 20px;"
        )
        email_layout = QVBoxLayout(frame_email)
        email_layout.setSpacing(14)

        # Header row with title and enable checkbox
        email_header_row = QHBoxLayout()
        lbl_email_title = QLabel("Email & Server Down Alerts")
        lbl_email_title.setStyleSheet("font-size: 16px; font-weight: 700; color: #ffffff;")
        email_header_row.addWidget(lbl_email_title)
        email_header_row.addStretch()

        self.chk_email_enabled = QCheckBox("Enable Email Alert Notifications")
        self.chk_email_enabled.setChecked(bool(self.settings.get("email_alerts_enabled", False)))
        self.chk_email_enabled.setStyleSheet("font-size: 13px; font-weight: 600; color: #38bdf8;")
        email_header_row.addWidget(self.chk_email_enabled)
        email_layout.addLayout(email_header_row)

        lbl_email_desc = QLabel(
            "Dispatches automated email notifications to one or multiple recipients when a server fails periodic checks and subsequent insurance retries."
        )
        lbl_email_desc.setWordWrap(True)
        lbl_email_desc.setStyleSheet("color: #94a3b8; font-size: 12px;")
        email_layout.addWidget(lbl_email_desc)

        # Grid of SMTP settings
        smtp_grid = QGridLayout()
        smtp_grid.setSpacing(10)

        # Row 0: Host, Port, Security
        lbl_host = QLabel("SMTP Host / Server:")
        lbl_host.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        self.txt_smtp_host = QLineEdit(str(self.settings.get("smtp_host", "")))
        self.txt_smtp_host.setPlaceholderText("e.g. smtp.gmail.com, mail.company.com")
        self.txt_smtp_host.setStyleSheet("background-color: #1e293b; border: 1px solid #334155; padding: 7px 10px; font-weight: 500; border-radius: 6px;")

        lbl_port = QLabel("Port:")
        lbl_port.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        self.spn_smtp_port = QSpinBox()
        self.spn_smtp_port.setRange(1, 65535)
        self.spn_smtp_port.setValue(int(self.settings.get("smtp_port", 587) or 587))
        self.spn_smtp_port.setStyleSheet("background-color: #1e293b; border: 1px solid #334155; padding: 6px 10px; font-weight: 500; border-radius: 6px;")

        lbl_sec = QLabel("Security Mode:")
        lbl_sec.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        self.cmb_smtp_security = QComboBox()
        self.cmb_smtp_security.addItem("STARTTLS", "STARTTLS")
        self.cmb_smtp_security.addItem("SSL/TLS", "SSL/TLS")
        self.cmb_smtp_security.addItem("None", "None")
        saved_sec = str(self.settings.get("smtp_security", "STARTTLS")).upper()
        sec_idx = 0
        if "SSL" in saved_sec:
            sec_idx = 1
        elif "NONE" in saved_sec:
            sec_idx = 2
        self.cmb_smtp_security.setCurrentIndex(sec_idx)
        self.cmb_smtp_security.setStyleSheet("background-color: #1e293b; border: 1px solid #334155; padding: 6px 10px; font-weight: 500; border-radius: 6px;")

        smtp_grid.addWidget(lbl_host, 0, 0)
        smtp_grid.addWidget(self.txt_smtp_host, 1, 0)
        smtp_grid.addWidget(lbl_port, 0, 1)
        smtp_grid.addWidget(self.spn_smtp_port, 1, 1)
        smtp_grid.addWidget(lbl_sec, 0, 2)
        smtp_grid.addWidget(self.cmb_smtp_security, 1, 2)

        # Row 1: Username, Password
        lbl_user = QLabel("SMTP Username / Auth Email:")
        lbl_user.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        self.txt_smtp_user = QLineEdit(str(self.settings.get("smtp_user", "")))
        self.txt_smtp_user.setPlaceholderText("e.g. alert-system@domain.com")
        self.txt_smtp_user.setStyleSheet("background-color: #1e293b; border: 1px solid #334155; padding: 7px 10px; font-weight: 500; border-radius: 6px;")

        lbl_pass = QLabel("SMTP Password / App Token:")
        lbl_pass.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        self.txt_smtp_password = QLineEdit(str(self.settings.get("smtp_password", "")))
        self.txt_smtp_password.setEchoMode(QLineEdit.Password)
        self.txt_smtp_password.setPlaceholderText("Password or App Password")
        self.txt_smtp_password.setStyleSheet("background-color: #1e293b; border: 1px solid #334155; padding: 7px 10px; font-weight: 500; border-radius: 6px;")

        smtp_grid.addWidget(lbl_user, 2, 0, 1, 2)
        smtp_grid.addWidget(self.txt_smtp_user, 3, 0, 1, 2)
        smtp_grid.addWidget(lbl_pass, 2, 2)
        smtp_grid.addWidget(self.txt_smtp_password, 3, 2)

        # Row 2: Sender (Optional)
        lbl_sender = QLabel("Sender Address (Optional):")
        lbl_sender.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        self.txt_smtp_sender = QLineEdit(str(self.settings.get("smtp_sender", "")))
        self.txt_smtp_sender.setPlaceholderText("Optional: ServerMon Alert <alerts@domain.com> (defaults to Username)")
        self.txt_smtp_sender.setStyleSheet("background-color: #1e293b; border: 1px solid #334155; padding: 7px 10px; font-weight: 500; border-radius: 6px;")
        smtp_grid.addWidget(lbl_sender, 4, 0, 1, 3)
        smtp_grid.addWidget(self.txt_smtp_sender, 5, 0, 1, 3)

        email_layout.addLayout(smtp_grid)

        # Recipients Multi-address input
        lbl_recipients = QLabel("Alert Recipient Email Addresses:")
        lbl_recipients.setStyleSheet("font-weight: 600; color: #cbd5e1; margin-top: 4px;")
        email_layout.addWidget(lbl_recipients)

        lbl_recipients_sub = QLabel("Enter one or several recipient email addresses (separated by commas, semicolons, or newlines):")
        lbl_recipients_sub.setStyleSheet("color: #94a3b8; font-size: 11px;")
        email_layout.addWidget(lbl_recipients_sub)

        self.txt_email_recipients = QTextEdit()
        self.txt_email_recipients.setPlainText(str(self.settings.get("email_recipients", "")))
        self.txt_email_recipients.setPlaceholderText("admin@company.com, oncall@company.com\noperations@team.net")
        self.txt_email_recipients.setMaximumHeight(65)
        self.txt_email_recipients.setStyleSheet(
            "background-color: #1e293b; border: 1px solid #334155; padding: 6px 10px; font-weight: 500; border-radius: 6px; color: #f8fafc;"
        )
        email_layout.addWidget(self.txt_email_recipients)

        # Action Buttons row
        actions_row = QHBoxLayout()
        self.btn_save_email = QPushButton("Save Email Settings")
        self.btn_save_email.setStyleSheet(
            "background-color: #2563eb; color: #ffffff; padding: 8px 18px; font-weight: 700; border-radius: 6px;"
        )
        self.btn_save_email.clicked.connect(self.handle_save_email_settings)

        self.btn_test_email = QPushButton("Send Test Email")
        self.btn_test_email.setStyleSheet(
            "background-color: #059669; color: #ffffff; padding: 8px 18px; font-weight: 700; border-radius: 6px;"
        )
        self.btn_test_email.clicked.connect(self.handle_send_test_email)

        self.lbl_email_feedback = QLabel()
        self.lbl_email_feedback.setStyleSheet("color: #94a3b8; font-size: 12px; font-weight: 600;")

        actions_row.addWidget(self.btn_save_email)
        actions_row.addWidget(self.btn_test_email)
        actions_row.addWidget(self.lbl_email_feedback)
        actions_row.addStretch()
        email_layout.addLayout(actions_row)

        # =====================================================================
        # SCROLL AREA WRAPPER FOR CLEAN ADAPTIVE LAYOUT
        # =====================================================================
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background: transparent;
            }
            QScrollBar:vertical {
                background: #0f172a;
                width: 8px;
                margin: 0px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: #334155;
                min-height: 24px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: #475569;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
        """)

        scroll_container = QWidget()
        scroll_container.setStyleSheet("background: transparent;")
        scroll_layout = QVBoxLayout(scroll_container)
        scroll_layout.setSpacing(18)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        scroll_layout.addWidget(frame_settings)
        scroll_layout.addWidget(frame_email)
        scroll_layout.addStretch(1)

        scroll_area.setWidget(scroll_container)

        # Remove the empty vertical spacer from gui.ui so scroll_area occupies the entire page height
        for i in reversed(range(layout.count())):
            item = layout.itemAt(i)
            if item and item.spacerItem():
                layout.removeItem(item)
                break

        layout.addWidget(scroll_area)
        layout.setStretchFactor(scroll_area, 1)

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

    def handle_insurance_retries_change(self, value: int):
        """Updates subsequent insurance retry count and persists to config."""
        self.insurance_retries = int(value)
        self.settings.set("insurance_retries", self.insurance_retries)
        self.scheduler.set_insurance_config(self.insurance_retries, self.insurance_delay_ms)

    def handle_save_email_settings(self):
        """Validates and persists SMTP email configuration and recipient list."""
        enabled = self.chk_email_enabled.isChecked()
        host = self.txt_smtp_host.text().strip()
        port = self.spn_smtp_port.value()
        security = self.cmb_smtp_security.currentData() or self.cmb_smtp_security.currentText()
        user = self.txt_smtp_user.text().strip()
        password = self.txt_smtp_password.text()
        sender = self.txt_smtp_sender.text().strip()
        recipients_raw = self.txt_email_recipients.toPlainText().strip()

        self.settings.set("email_alerts_enabled", enabled)
        self.settings.set("smtp_host", host)
        self.settings.set("smtp_port", port)
        self.settings.set("smtp_security", security)
        self.settings.set("smtp_user", user)
        self.settings.set("smtp_password", password)
        self.settings.set("smtp_sender", sender)
        self.settings.set("email_recipients", recipients_raw)

        clean_recipients = parse_recipients(recipients_raw)
        if enabled and not host:
            self.lbl_email_feedback.setText("⚠ Settings saved, but SMTP Host is required!")
            self.lbl_email_feedback.setStyleSheet("color: #f59e0b; font-size: 12px; font-weight: 600;")
            QMessageBox.warning(
                self.window, "Missing SMTP Host",
                "Email alerts are enabled, but no SMTP Host was configured.\n"
                "Please enter an SMTP server (e.g. smtp.gmail.com)."
            )
        elif enabled and not clean_recipients:
            self.lbl_email_feedback.setText("⚠ Settings saved, but no valid recipients found!")
            self.lbl_email_feedback.setStyleSheet("color: #f59e0b; font-size: 12px; font-weight: 600;")
            QMessageBox.warning(
                self.window, "No Recipients",
                "Email alerts are enabled, but no valid recipient email addresses were found.\n"
                "Please add at least one recipient address (e.g. admin@domain.com)."
            )
        else:
            self.lbl_email_feedback.setText(f"✓ Saved! ({len(clean_recipients)} recipient address(es) configured)")
            self.lbl_email_feedback.setStyleSheet("color: #34d399; font-size: 12px; font-weight: 600;")

    def handle_send_test_email(self):
        """Sends an asynchronous test email using current form values."""
        host = self.txt_smtp_host.text().strip()
        port = self.spn_smtp_port.value()
        security = self.cmb_smtp_security.currentData() or self.cmb_smtp_security.currentText()
        user = self.txt_smtp_user.text().strip()
        password = self.txt_smtp_password.text()
        sender = self.txt_smtp_sender.text().strip()
        recipients_raw = self.txt_email_recipients.toPlainText().strip()

        if not host:
            QMessageBox.warning(
                self.window, "Missing SMTP Host",
                "Please enter an SMTP Host address before sending a test email."
            )
            return

        recipients = parse_recipients(recipients_raw)
        if not recipients:
            QMessageBox.warning(
                self.window, "Missing Recipients",
                "Please enter at least one valid recipient email address in the recipients box."
            )
            return

        smtp_config = {
            "smtp_host": host,
            "smtp_port": port,
            "smtp_security": security,
            "smtp_user": user,
            "smtp_password": password,
            "smtp_sender": sender,
        }

        subject, text_body, html_body = notifier.format_test_email(len(recipients))

        self.btn_test_email.setEnabled(False)
        self.lbl_email_feedback.setText(f"Dispatching test email to {len(recipients)} recipient(s)...")
        self.lbl_email_feedback.setStyleSheet("color: #38bdf8; font-size: 12px; font-weight: 600;")

        def _on_test_finished(success: bool, msg: str):
            self.btn_test_email.setEnabled(True)
            if success:
                self.lbl_email_feedback.setText(f"✓ {msg}")
                self.lbl_email_feedback.setStyleSheet("color: #34d399; font-size: 12px; font-weight: 600;")
                QMessageBox.information(
                    self.window, "Test Email Successful",
                    f"Test email was delivered successfully!\n\n{msg}"
                )
            else:
                self.lbl_email_feedback.setText(f"✗ Delivery failed: {msg}")
                self.lbl_email_feedback.setStyleSheet("color: #f87171; font-size: 12px; font-weight: 600;")
                QMessageBox.warning(
                    self.window, "Test Email Failed",
                    f"Failed to dispatch test email:\n\n{msg}"
                )

        self.notifier.send_async(
            smtp_config=smtp_config,
            recipients=recipients,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            callback=_on_test_finished
        )

    def _on_server_down_alert(self, target: dict, result: dict):
        """Dispatches desktop and email alerts when a server is confirmed DOWN."""
        name = target.get("name", "Unknown Server")
        host = target.get("host", "Unknown Host")
        retries = self.insurance_retries + 1
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{now_str} - CRITICAL - ALERT: Server '{name}' ({host}) is DOWN after {retries} consecutive failed checks!"
        logging.critical(log_entry)
        if hasattr(self.window, "txt_audit_logs"):
            self.window.txt_audit_logs.append(log_entry)

        self.notifier.notify_server_down(
            target=target,
            result=result,
            smtp_config=self.settings.get_smtp_config(),
            retries_done=retries
        )

    def _on_server_recovered_alert(self, target: dict, result: dict):
        """Dispatches recovery notifications when a server returns ONLINE."""
        name = target.get("name", "Unknown Server")
        host = target.get("host", "Unknown Host")
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{now_str} - INFO - RECOVERED: Server '{name}' ({host}) is back ONLINE."
        logging.info(log_entry)
        if hasattr(self.window, "txt_audit_logs"):
            self.window.txt_audit_logs.append(log_entry)

        self.notifier.notify_server_recovered(
            target=target,
            result=result,
            smtp_config=self.settings.get_smtp_config()
        )

    def _on_insurance_attempt(self, target: dict, attempt: int, total: int):
        """Logs subsequent insurance verification attempt for a suspect server."""
        name = target.get("name", "Unknown Server")
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{now_str} - WARNING - INSURANCE: {name} | Check failed. Running insurance check #{attempt}/{total}..."
        logging.warning(log_entry)
        if hasattr(self.window, "txt_audit_logs"):
            self.window.txt_audit_logs.append(log_entry)

    def _on_email_dispatched(self, success: bool, msg: str):
        """Logs asynchronous email dispatch outcome to live audit logs."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lvl = "INFO" if success else "WARNING"
        log_entry = f"{now_str} - {lvl} - EMAIL DISPATCH: {msg}"
        if success:
            logging.info(log_entry)
        else:
            logging.warning(log_entry)
        if hasattr(self.window, "txt_audit_logs"):
            self.window.txt_audit_logs.append(log_entry)

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
            # Process result through scheduler insurance verification
            outcome = self.scheduler.handle_check_result(target, result)
            if outcome == "INSURANCE_CHECKING":
                target["status"] = "VERIFYING"
            elif outcome == "CONFIRMED_DOWN":
                target["status"] = "OFFLINE"
            elif outcome in ("ONLINE", "RECOVERED"):
                target["status"] = result.get("overall_status") or "ONLINE"
            elif outcome == "STILL_OFFLINE":
                target["status"] = "OFFLINE"
            else:
                target["status"] = result.get("overall_status") or result.get("status", "OFFLINE")

            # 1. Update in-memory telemetry
            target["resolved_ip"] = result.get("resolved_ip") or target.get("resolved_ip")
            target["response_time_ms"] = result.get("response_time_ms")
            target["last_checked"] = check_time
            target["error"] = result.get("error")

            # Append rolling history telemetry sample for all evaluated checks
            multi_checks = result.get("multi_checks")
            if multi_checks and isinstance(multi_checks, dict):
                for chk_name, chk_data in multi_checks.items():
                    if isinstance(chk_data, dict):
                        storageH.append_telemetry_sample(target, chk_name, chk_data)
            else:
                storageH.append_telemetry_sample(target, mode, result)

            # 2. Update math counters
            self._update_target_counters(target, target["status"], result.get("response_time_ms"), check_mode=mode)
            self._refresh_target_ui(target)

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
        self.active_scheduled_target_ids.clear()

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

        # 5. Conclude active email dispatch workers and hide tray icon
        self.notifier.stop_all(500)

        # 6. Synchronously flush all dirty target states and metrics to disk
        self.flush_targets_to_disk()
        self._save_storage_metrics()

        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    ui = NetworkMonitorUI("gui.ui")
    ui.show()
    sys.exit(app.exec())