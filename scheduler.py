from PySide6.QtCore import QTimer, QObject, Signal


class ServerScheduler(QObject):
    """
    Manages independent background check schedules for individual servers,
    with built-in insurance verification retries before declaring a server DOWN.
    """

    # Emitted when a check should run: (target_dict, reason_str: 'SCHEDULED' | 'INSURANCE')
    check_requested = Signal(dict, str)

    # Emitted when an insurance verification retry is initiated: (target_dict, attempt_int, max_retries_int)
    insurance_attempt = Signal(dict, int, int)

    # Emitted ONLY after initial check and all subsequent insurance checks fail: (target_dict, last_result_dict)
    server_down = Signal(dict, dict)

    # Emitted when a previously DOWN server returns ONLINE: (target_dict, result_dict)
    server_recovered = Signal(dict, dict)

    def __init__(
        self,
        normal_interval_ms: int = 60000,
        offline_interval_ms: int = 30000,
        insurance_retries: int = 2,
        insurance_delay_ms: int = 1000
    ):
        """Initializes scheduler intervals, insurance check limits, and active timer tracking."""
        super().__init__()
        self.timers = {}              # target_id -> recurring QTimer
        self.insurance_timers = {}    # target_id -> single-shot QTimer for pending insurance retries
        self.failure_counts = {}      # target_id -> consecutive failure count in current verification cycle
        self.server_states = {}       # target_id -> last confirmed status ('ONLINE', 'OFFLINE', 'PENDING')
        self.in_insurance = set()     # set of target_ids currently undergoing insurance verification

        self.normal_interval = normal_interval_ms
        self.offline_interval = offline_interval_ms
        self.insurance_retries = max(0, int(insurance_retries))
        self.insurance_delay_ms = max(100, int(insurance_delay_ms))

    def set_insurance_config(self, retries: int, delay_ms: int = 1000):
        """Updates insurance check retry count and inter-retry delay."""
        self.insurance_retries = max(0, int(retries))
        self.insurance_delay_ms = max(100, int(delay_ms))

    def start_server_scheduler(self, target: dict, delay_ms: int = 0):
        """Starts an independent recurring check timer for a target."""
        target_id = target.get("id")
        if not target_id:
            return

        self.stop_server_scheduler(target_id)
        target_st = target.get("status", "ONLINE")
        self.server_states[target_id] = "PENDING" if target_st == "OFFLINE" else "ONLINE"

        timer = QTimer(self)
        timer.timeout.connect(lambda t=target: self.check_requested.emit(t, "SCHEDULED"))
        self.timers[target_id] = timer

        st = self.server_states.get(target_id, "ONLINE")
        cur_ms = self.normal_interval if st != "OFFLINE" else self.offline_interval
        timer.start(cur_ms)

        if delay_ms > 0:
            QTimer.singleShot(delay_ms, lambda t=target: self.check_requested.emit(t, "SCHEDULED"))
        else:
            self.check_requested.emit(target, "SCHEDULED")

    def handle_check_result(self, target: dict, result: dict) -> str:
        """
        Processes check results through the insurance verification state machine.
        Flow: check -> fail -> subsequent insurance checks -> only then declare DOWN & alert.

        Returns one of:
            'ONLINE'              - Server responded successfully; healthy.
            'RECOVERED'           - Server transitioned from OFFLINE back to ONLINE.
            'INSURANCE_CHECKING'  - Initial check failed; insurance retry queued.
            'CONFIRMED_DOWN'      - All insurance checks failed; server officially DOWN.
            'STILL_OFFLINE'       - Server was already confirmed OFFLINE; recurring check confirmed.
        """
        if not target or not isinstance(target, dict):
            return "UNKNOWN"
        target_id = target.get("id")
        if not target_id:
            return "UNKNOWN"

        if not result or not isinstance(result, dict):
            return "UNKNOWN"

        status = result.get("overall_status") or result.get("status", "OFFLINE")
        prev_state = self.server_states.get(target_id, "PENDING")

        # --- CASE 1: TARGET RESPONDED ONLINE (OR REACHABLE / DEGRADED / WARNING) ---
        if status in ("ONLINE", "DEGRADED", "WARNING"):
            # Clear any pending insurance state or failure tally
            self.in_insurance.discard(target_id)
            self.failure_counts[target_id] = 0

            # Cancel any pending insurance timer
            if target_id in self.insurance_timers:
                self.insurance_timers[target_id].stop()
                del self.insurance_timers[target_id]

            was_offline = (prev_state == "OFFLINE")
            self.server_states[target_id] = "ONLINE"

            # Resume normal cadence timer if it was paused
            self.update_status(target_id, "ONLINE")

            if was_offline:
                self.server_recovered.emit(target, result)
                return "RECOVERED"
            else:
                return "ONLINE"

        # --- CASE 2: TARGET FAILED TO RESPOND (OFFLINE) ---
        # If server was already confirmed OFFLINE and not currently in insurance testing,
        # recurring checks confirm it is still offline while AlertNotifier's 30s batch timer handles desktop alerts.
        if prev_state == "OFFLINE" and target_id not in self.in_insurance:
            self.update_status(target_id, "OFFLINE")
            return "STILL_OFFLINE"

        # Increment failure tally for this incident
        current_failures = self.failure_counts.get(target_id, 0) + 1
        self.failure_counts[target_id] = current_failures

        # Check if more insurance attempts remain before officially declaring DOWN
        if current_failures <= self.insurance_retries:
            self.in_insurance.add(target_id)

            # Pause recurring timer while rapid insurance verification is in flight
            if target_id in self.timers:
                self.timers[target_id].stop()

            # Stop existing insurance timer if any
            if target_id in self.insurance_timers:
                self.insurance_timers[target_id].stop()

            insurance_timer = QTimer(self)
            insurance_timer.setSingleShot(True)
            self.insurance_timers[target_id] = insurance_timer

            def _fire_insurance_retry(t=target, attempt=current_failures):
                if target_id in self.in_insurance:
                    self.insurance_attempt.emit(t, attempt, self.insurance_retries)
                    self.check_requested.emit(t, "INSURANCE")

            insurance_timer.timeout.connect(_fire_insurance_retry)
            insurance_timer.start(self.insurance_delay_ms)
            return "INSURANCE_CHECKING"

        # --- ALL INSURANCE RETRIES FAILED -> CONFIRMED DOWN ---
        self.in_insurance.discard(target_id)
        self.failure_counts[target_id] = 0
        self.server_states[target_id] = "OFFLINE"

        if target_id in self.insurance_timers:
            self.insurance_timers[target_id].stop()
            del self.insurance_timers[target_id]

        # Switch to offline interval
        self.update_status(target_id, "OFFLINE")

        # Emit confirmed server_down signal for alert & email dispatch
        self.server_down.emit(target, result)
        return "CONFIRMED_DOWN"

    def update_status(self, target_id: str, status: str):
        """Dynamically adjusts interval based on online/offline health status without corrupting state."""
        timer = self.timers.get(target_id)
        if not timer:
            return

        # Do not restart recurring cadence if rapid insurance checks are currently in progress
        if target_id in self.in_insurance:
            return

        new_interval = self.normal_interval if status != "OFFLINE" else self.offline_interval
        if timer.interval() != new_interval or not timer.isActive():
            timer.start(new_interval)

    def get_server_state(self, target_id: str) -> str:
        """Returns the scheduler's confirmed state ('ONLINE', 'OFFLINE', 'VERIFYING', 'UNKNOWN')."""
        if target_id in self.in_insurance:
            return "VERIFYING"
        return self.server_states.get(target_id, "UNKNOWN")

    def set_intervals(self, normal_sec: int, offline_sec: int, targets: list = None):
        """Updates base intervals and recalculates running timers."""
        self.normal_interval = int(normal_sec * 1000)
        self.offline_interval = int(offline_sec * 1000)

        if targets:
            lookup = {t.get("id"): t.get("status") for t in targets if t.get("id")}
            for tid, timer in self.timers.items():
                st = lookup.get(tid, self.server_states.get(tid, "ONLINE"))
                new_ms = self.normal_interval if st != "OFFLINE" else self.offline_interval
                timer.setInterval(new_ms)

    def stop_server_scheduler(self, target_id: str):
        """Stops and removes the recurring and insurance timers for a specific server."""
        if target_id in self.timers:
            self.timers[target_id].stop()
            del self.timers[target_id]

        if target_id in self.insurance_timers:
            self.insurance_timers[target_id].stop()
            del self.insurance_timers[target_id]

        self.in_insurance.discard(target_id)
        self.failure_counts.pop(target_id, None)
        self.server_states.pop(target_id, None)

    def stop_all(self):
        """Stops all running recurring and insurance timers and clears state."""
        for timer in self.timers.values():
            timer.stop()
        self.timers.clear()

        for itimer in self.insurance_timers.values():
            itimer.stop()
        self.insurance_timers.clear()

        self.in_insurance.clear()
        self.failure_counts.clear()
        self.server_states.clear()