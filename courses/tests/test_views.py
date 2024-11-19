from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth import get_user_model
from courses.models import Course


class CourseViewTest(APITestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username='testuser', password='password123', role='teacher')
        self.client.login(username='testuser', password='password123')

        self.course = Course.objects.create(
            name='Test Course',
            description='A sample course',
            teacher_id=self.user
        )

    def test_course_list(self):
        response = self.client.get('/api/courses/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_course_create(self):
        data = {'name': 'New Course', 'description': 'New course description', 'teacher_id': self.user.id}
        response = self.client.post('/api/courses/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_course_detail(self):
        response = self.client.get(f'/api/courses/{self.course.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_course_update(self):
        data = {'name': 'Updated Course', 'description': 'Updated description', 'teacher_id': self.user.id}
        response = self.client.put(f'/api/courses/{self.course.id}/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_course_delete(self):
        response = self.client.delete(f'/api/courses/{self.course.id}/')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
