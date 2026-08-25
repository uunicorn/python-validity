import logging

from .sensor import FingerNotMatchedException


class CaptureRetryNotifier:
    """Report rejected captures without inventing a daemon-side timeout.

    A blank frame, poor contact, and the previously described chip wedge all
    produce the same callback. Only the D-Bus client has an authoritative
    timeout/cancellation policy, so this notifier never cancels the sensor.
    """

    def __init__(self, user, emit, log=logging.info):
        self.user = user
        self.emit = emit
        self.log = log
        self.count = 0
        self.emitted = False

    def __call__(self, error):
        self.count += 1
        self.log('Chip capture retry-scan #%d (user=%s)',
                 self.count, self.user)
        if not self.emitted:
            self.emit('verify-retry-scan', False)
            self.emitted = True


def identify_with_retries(identify, update_cb, retry_cb, max_attempts=3):
    """Retry only clean on-chip no-template results, up to a fixed limit."""
    if max_attempts < 1:
        raise ValueError('max_attempts must be at least one')

    for attempt in range(1, max_attempts + 1):
        try:
            return identify(update_cb)
        except FingerNotMatchedException:
            if attempt == max_attempts:
                raise
            retry_cb(attempt, max_attempts)
