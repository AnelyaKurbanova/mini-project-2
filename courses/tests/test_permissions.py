from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth import get_user_model
from courses.models import Course

class TestPermissions(APITestCase):
    def setUp(self):
        self.user_student = get_user_model().objects.create_user(username='student', password='password123', role='student')
        self.user_teacher = get_user_model().objects.create_user(username='teacher', password='password123', role='teacher')

        self.client.login(username='teacher', password='password123')

    def test_teacher_can_access_course(self):
        course = Course.objects.create(
            name='Test Course',
            description='A sample course',
            teacher_id=self.user_teacher
        )
        response = self.client.get(f'/api/courses/{course.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_student_cannot_access_course(self):
        course = Course.objects.create(
            name='Test Course',
            description='A sample course',
            teacher_id=self.user_teacher
        )
        self.client.login(username='student', password='password123')
        response = self.client.get(f'/api/courses/{course.id}/')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
