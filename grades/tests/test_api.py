from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from courses.models import Course
from grades.models import Grade


class GradeApiTests(TestCase):

    def setUp(self):
        Grade.objects.all().delete()
        Course.objects.all().delete()

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

    def test_create_grade(self):
        """Test creating a grade through the API."""
        self.client.force_authenticate(user=self.teacher)
        url = '/api/grades/'
        data = {
            'student_id': self.student.id,
            'course_id': self.course.id,
            'grade': 'B'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['grade'], 'B')

    def test_list_grades(self):
        """Test retrieving a list of grades."""
        self.client.force_authenticate(user=self.teacher)
        url = '/api/grades/'
        response = self.client.get(url)


        self.assertEqual(response.status_code, status.HTTP_200_OK)

        grades = Grade.objects.filter(teacher_id=self.teacher)
        results = response.data['results']  # Extract the results from the paginated response
        self.assertEqual(len(results), grades.count())

        returned_grade = results[0]
        self.assertEqual(returned_grade['student_id'], self.student.id)
        self.assertEqual(returned_grade['course_id'], self.course.id)
        self.assertEqual(returned_grade['grade'], 'A')

    def test_view_grade(self):
        """Test retrieving a specific grade."""
        self.client.force_authenticate(user=self.teacher)
        url = f'/api/grades/{self.grade.id}/'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['grade'], 'A')

    def test_update_grade(self):
        """Test updating a grade."""
        self.client.force_authenticate(user=self.teacher)
        url = f'/api/grades/{self.grade.id}/'
        data = {
            'grade': 'B',
            'student_id': self.student.id,
            'course_id': self.course.id,  # Include the course ID
        }
        response = self.client.put(url, data, format='json')


        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['grade'], 'B')

    def test_delete_grade(self):
        """Test deleting a grade."""
        self.client.force_authenticate(user=self.teacher)
        url = f'/api/grades/{self.grade.id}/'
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Grade.objects.count(), 0)
