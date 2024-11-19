from celery import current_app
from celery.result import EagerResult
from django.test import TestCase
from unittest.mock import patch
from notifications.tasks import test_task, add_numbers


class CeleryTaskTests(TestCase):
    def setUp(self):
        self.celery_always_eager = True

    def test_test_task(self):
        """Test if the test task is triggered and executed correctly."""
        with patch("notifications.tasks.print") as mock_print:
            result = test_task.apply()
            self.assertEqual(result.status, "SUCCESS")
            self.assertEqual(result.result, "Task completed")
            mock_print.assert_called_with("Test task executed")

    def test_add_numbers_task(self):
        """Test if the add_numbers task adds numbers correctly."""
        result = add_numbers.apply((4, 5))
        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.result, 9)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._task_always_eager = current_app.conf.task_always_eager
        current_app.conf.task_always_eager = True
        cls._task_eager_propagates = current_app.conf.task_eager_propagates
        current_app.conf.task_eager_propagates = True

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        current_app.conf.task_always_eager = cls._task_always_eager
        current_app.conf.task_eager_propagates = cls._task_eager_propagates

    def test_add_numbers_asynchronous(self):
        """Test the asynchronous execution of a Celery task."""
        result = add_numbers.delay(10, 15)
        self.assertIsInstance(result, EagerResult)
        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.result, 25)