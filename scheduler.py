from PySide6.QtCore import QTimer, QObject, Signal

class ServerScheduler(QObject):
    """
    Manages independent background check schedules for individual servers.
    
    Why this architecture works cleanly:
    1. Independent timers: Each server has its own dedicated QTimer rather than one
       global clock checking all servers simultaneously. This spaces out network checks.
    2. Adaptive intervals: Servers in a healthy ("ONLINE") state are checked every 60s.
       If a server is detected as "OFFLINE", its check interval tightens to 30s.
    3. GUI & Thread safety: QTimer runs on Qt's main thread event loop. When it fires,
       it emits `check_requested` carrying the server's data. A worker thread is spawned
       to do the blocking ping/TCP check, keeping the GUI running at full speed without lag.
    """

    # Qt Signal emitted whenever any server's timer ticks.
    # The payload is the target dictionary (id, host, port, check_type, etc.).
    check_requested = Signal(dict)

    def __init__(self, normal_interval_ms: int = 60000, offline_interval_ms: int = 30000):
        super().__init__()
        # Dictionary mapping target_id -> QTimer instance
        self.timers = {}
        # 60 seconds for healthy servers
        self.normal_interval = normal_interval_ms
        # 30 seconds for down/failing servers
        self.offline_interval = offline_interval_ms

    def start_server_scheduler(self, target: dict, delay_ms: int = 0):
        """
        Starts an independent timer for a given server target.
        - Emits an immediate initial check so the user doesn't wait 60s for the first result.
        - Sets up recurring ticks based on normal_interval.
        """
        target_id = target.get("id")
        if not target_id:
            return

        # Clean up any pre-existing timer for this server (e.g. if edited or restarted)
        self.stop_server_scheduler(target_id)


        # Create a new QTimer parented to self
        timer = QTimer(self)

        # Connect the timer's timeout to emit check_requested with this specific target.
        # Notice `t=target`: Default argument binding ensures the lambda captures
        # THIS server dictionary rather than referencing whatever target was processed last.
        timer.timeout.connect(lambda t=target: self.check_requested.emit(t))

        # Save reference in lookup dictionary
        self.timers[target_id] = timer
        
        # Timer Stagger & Startup
        if delay_ms > 0:
            # Staggered start: wait delay_ms before starting the recurring timer and firing
            def _start_staggered():
                if target_id in self.timers:
                    timer.start(self.normal_interval)
                    self.check_requested.emit(target)

            QTimer.singleShot(delay_ms, _start_staggered)
        else:
            # Immediate start
            timer.start(self.normal_interval)
            self.check_requested.emit(target)

    def update_status(self, target_id: str, status: str):
        """
        Adjusts the timing cadence dynamically based on recent check results:
        - If ONLINE: 60,000 ms (60 seconds)
        - If OFFLINE: 30,000 ms (30 seconds)
        
        If the interval changed (e.g. server went offline or recovered),
        timer.start(new_interval) is called to reset the countdown immediately
        to the new interval instead of waiting for the remainder of the old one.
        """
        # Step 1: Look up this specific server's timer
        timer = self.timers.get(target_id)
        if not timer:
            return

        # Step 2: Determine appropriate interval
        new_interval = self.normal_interval if status == "ONLINE" else self.offline_interval

        # Step 3: If interval changed, restart with the new interval immediately
        if timer.interval() != new_interval:
            timer.start(new_interval)

    def set_intervals(self, normal_sec: int, offline_sec: int, targets: list = None):
        """
        Updates the default check intervals (in seconds) and recalculates running timers.
        """
        self.normal_interval = int(normal_sec * 1000)
        self.offline_interval = int(offline_sec * 1000)

        # Update running timers immediately if targets list provided
        if targets:
            lookup = {t.get("id"): t.get("status") for t in targets if t.get("id")}
            for tid, timer in self.timers.items():
                st = lookup.get(tid, "ONLINE")
                new_ms = self.normal_interval if st == "ONLINE" else self.offline_interval
                timer.setInterval(new_ms)

    def stop_server_scheduler(self, target_id: str):
        """
        Stops and removes the timer for a specific server (e.g., when deleted).
        """
        if target_id in self.timers:
            self.timers[target_id].stop()
            del self.timers[target_id]

    def stop_all(self):
        """
        Stops all running timers. Useful during application exit.
        """
        for timer in self.timers.values():
            timer.stop()
        self.timers.clear()
            