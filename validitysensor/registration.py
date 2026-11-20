class RetryingRegistrar:
    """Register against a replaceable D-Bus owner with capped backoff."""

    def __init__(self, register, schedule, on_error=None,
                 initial_delay=1, max_delay=30):
        self.register = register
        self.schedule = schedule
        self.on_error = on_error or (lambda error, attempt, delay: None)
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.generation = 0
        self.owner = ''

    def owner_changed(self, owner):
        self.generation += 1
        self.owner = owner
        if owner:
            self._attempt(self.generation, 1)

    def _attempt(self, generation, attempt):
        # GLib timeout callbacks must return False to run only once. A stale
        # callback from a previous D-Bus owner must never register against the
        # replacement manager.
        if generation != self.generation or not self.owner:
            return False
        try:
            self.register(self.owner)
        except Exception as error:
            delay = min(
                self.initial_delay * (2 ** (attempt - 1)),
                self.max_delay,
            )
            self.on_error(error, attempt, delay)
            self.schedule(delay, self._attempt, generation, attempt + 1)
        return False
