import unittest
from threading import Event

from validitysensor.operation import OperationBusy, OperationController


class OperationControllerTests(unittest.TestCase):
    def test_new_operation_cancels_and_joins_abandoned_worker(self):
        cancel = Event()
        first_started = Event()
        second_finished = Event()
        begin_count = []
        controller = OperationController(lambda: begin_count.append(1), cancel.set)

        def first():
            first_started.set()
            cancel.wait()

        controller.start(first)
        self.assertTrue(first_started.wait(1))
        controller.start(second_finished.set)
        self.assertTrue(second_finished.wait(1))
        self.assertEqual(len(begin_count), 2)

    def test_refuses_overlap_when_worker_ignores_cancellation(self):
        release = Event()
        started = Event()
        controller = OperationController(lambda: None, lambda: None)

        def stuck():
            started.set()
            release.wait()

        controller.start(stuck)
        self.assertTrue(started.wait(1))
        with self.assertRaises(OperationBusy):
            controller.start(lambda: None, retire_timeout=0.01)
        release.set()
        self.assertTrue(controller.cancel(timeout=1))


if __name__ == '__main__':
    unittest.main()
