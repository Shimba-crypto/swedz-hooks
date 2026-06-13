import threading
import time
import psutil
from typing import Callable, Optional

class ProcessWatchdog:
    def __init__(self, process, check_interval=1.0, on_exit: Optional[Callable] = None):
        self.process = process
        self.pid = process.pid
        self.interval = check_interval
        self.on_exit = on_exit
        self._stop_event = threading.Event()
        self._thread = None

    def _monitor(self):
        while not self._stop_event.is_set():
            if not psutil.pid_exists(self.pid):
                if self.on_exit:
                    self.on_exit(self.pid)
                break
            time.sleep(self.interval)

    def start(self):
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1)
