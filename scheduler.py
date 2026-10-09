from PySide6.QtCore import QTimer, QObject, Signal


class ServerScheduler(QObject):
    """Manages independent background check schedules for individual servers."""

    check_requested = Signal(dict)

    def __init__(self, normal_interval_ms: int = 60000, offline_interval_ms: int = 30000):
        """Initializes scheduler intervals and active timer dictionary."""
        super().__init__()
        self.timers = {}
        self.normal_interval = normal_interval_ms
        self.offline_interval = offline_interval_ms

    def start_server_scheduler(self, target: dict, delay_ms: int = 0):
        """Starts an independent recurring check timer for a target."""
        target_id = target.get("id")
        if not target_id:
            return

        self.stop_server_scheduler(target_id)
        timer = QTimer(self)
        timer.timeout.connect(lambda t=target: self.check_requested.emit(t))
        self.timers[target_id] = timer

        if delay_ms > 0:
            def _start_staggered():
                """Starts timer after initial stagger delay."""
                if target_id in self.timers:
                    timer.start(self.normal_interval)
                    self.check_requested.emit(target)

            QTimer.singleShot(delay_ms, _start_staggered)
        else:
            timer.start(self.normal_interval)
            self.check_requested.emit(target)

    def update_status(self, target_id: str, status: str):
        """Dynamically adjusts interval based on online/offline health status."""
        timer = self.timers.get(target_id)
        if not timer:
            return

        new_interval = self.normal_interval if status == "ONLINE" else self.offline_interval
        if timer.interval() != new_interval:
            timer.start(new_interval)

    def set_intervals(self, normal_sec: int, offline_sec: int, targets: list = None):
        """Updates base intervals and recalculates running timers."""
        self.normal_interval = int(normal_sec * 1000)
        self.offline_interval = int(offline_sec * 1000)

        if targets:
            lookup = {t.get("id"): t.get("status") for t in targets if t.get("id")}
            for tid, timer in self.timers.items():
                st = lookup.get(tid, "ONLINE")
                new_ms = self.normal_interval if st == "ONLINE" else self.offline_interval
                timer.setInterval(new_ms)

    def stop_server_scheduler(self, target_id: str):
        """Stops and removes the timer for a specific server."""
        if target_id in self.timers:
            self.timers[target_id].stop()
            del self.timers[target_id]

    def stop_all(self):
        """Stops all running timers."""
        for timer in self.timers.values():
            timer.stop()
        self.timers.clear()