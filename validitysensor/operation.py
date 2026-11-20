from threading import Lock, Thread, current_thread


class OperationBusy(Exception):
    pass


class OperationController:
    """Serialize access to a single sensor and retire abandoned workers."""

    def __init__(self, begin, cancel):
        self.begin = begin
        self.cancel_callback = cancel
        self.start_lock = Lock()
        self.state_lock = Lock()
        self.active_thread = None

    def cancel(self, timeout=None):
        with self.state_lock:
            active = self.active_thread
        if active is None or not active.is_alive():
            return True
        self.cancel_callback()
        if timeout is not None:
            active.join(timeout=timeout)
        return not active.is_alive()

    def start(self, target, retire_timeout=2):
        with self.start_lock:
            if not self.cancel(timeout=retire_timeout):
                raise OperationBusy()

            self.begin()

            def owned_target():
                try:
                    target()
                finally:
                    with self.state_lock:
                        if self.active_thread is current_thread():
                            self.active_thread = None

            thread = Thread(target=owned_target, daemon=True)
            with self.state_lock:
                self.active_thread = thread
            thread.start()
            return thread
