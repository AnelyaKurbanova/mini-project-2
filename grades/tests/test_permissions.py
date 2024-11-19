from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

from courses.models import Course
from grades.models import Grade


class GradeApiPermissionsTest(TestCase):

    def setUp(self):
        self.client = APIClient()

        self.teacher = get_user_model().objects.create_user(
            username='teacher', password='password123', role='teacher'
        )
        self.student = get_user_model().objects.create_user(
            username='student', password='password123', role='student'
        )


        self.course = Course.objects.create(
            name='Math 101',
            description='Introduction to Mathematics',
            teacher_id=self.teacher
        )
        self.grade = Grade.objects.create(
            student_id=self.student,
            course_id=self.course,
            grade='A',
            teacher_id=self.teacher
        )

    def test_student_access(self):
        """Test student access permissions."""
        self.client.force_authenticate(user=self.student)
        url = f'/api/grades/{self.grade.id}/'

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data = {'grade': 'B'}
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_teacher_access(self):
        """Test teacher access permissions."""
        self.client.force_authenticate(user=self.teacher)
        url = f'/api/grades/{self.grade.id}/'

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


        data = {
            'grade': 'B',
            'student_id': self.student.id,
            'course_id': self.course.id
        }
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['grade'], 'B')

        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
