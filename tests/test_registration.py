import unittest

from validitysensor.registration import RetryingRegistrar


class RegistrationRetryTests(unittest.TestCase):
    def test_retries_startup_race_then_registers(self):
        attempts = []
        scheduled = []
        errors = []

        def register(owner):
            attempts.append(owner)
            if len(attempts) == 1:
                raise RuntimeError('manager not ready')

        registrar = RetryingRegistrar(
            register,
            lambda delay, callback, *args: scheduled.append(
                (delay, callback, args)),
            lambda *args: errors.append(args),
        )
        registrar.owner_changed(':1.10')

        self.assertEqual(attempts, [':1.10'])
        self.assertEqual(errors[0][1:], (1, 1))
        delay, callback, args = scheduled.pop()
        self.assertEqual(delay, 1)
        self.assertFalse(callback(*args))
        self.assertEqual(attempts, [':1.10', ':1.10'])
        self.assertEqual(scheduled, [])

    def test_owner_change_invalidates_scheduled_retry(self):
        attempts = []
        scheduled = []

        def register(owner):
            attempts.append(owner)
            if owner == ':1.10':
                raise RuntimeError('old manager disappeared')

        registrar = RetryingRegistrar(
            register,
            lambda delay, callback, *args: scheduled.append(
                (callback, args)),
        )
        registrar.owner_changed(':1.10')
        old_callback, old_args = scheduled.pop()
        registrar.owner_changed(':1.11')

        self.assertFalse(old_callback(*old_args))
        self.assertEqual(attempts, [':1.10', ':1.11'])

    def test_retry_delay_is_capped(self):
        scheduled = []
        registrar = RetryingRegistrar(
            lambda owner: (_ for _ in ()).throw(RuntimeError('not ready')),
            lambda delay, callback, *args: scheduled.append(delay),
            initial_delay=2,
            max_delay=30,
        )

        registrar.owner_changed(':1.10')
        registrar._attempt(registrar.generation, 10)
        self.assertEqual(scheduled, [2, 30])


if __name__ == '__main__':
    unittest.main()
