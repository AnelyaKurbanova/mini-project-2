from django.core.cache import cache
from rest_framework.test import APITestCase
from rest_framework import status
from courses.models import Course
from django.contrib.auth import get_user_model


class CacheTest(APITestCase):
    def setUp(self):
        # Create a teacher user
        self.user = get_user_model().objects.create_user(
            username='testuser',
            password='password123',
            role='teacher'
        )
        self.client.login(username='testuser', password='password123')

        self.course = Course.objects.create(
            name='Test Course',
            description='A sample course',
            teacher_id=self.user
        )

    def test_cache_miss_and_hit(self):
        """Test caching mechanism with course retrieval"""
        response = self.client.get('/api/courses/')
        self.assertEqual(response.status_code, status.HTTP_200_OK, "First request failed.")

        cache_key = f'courses_{self.user.id}'
        cached_data = cache.get(cache_key)
        self.assertIsNotNone(cached_data, "Cache is not populated after the first request.")
        self.assertGreater(len(cached_data), 0, "Cache is empty after the first request.")


        response = self.client.get('/api/courses/')
        self.assertEqual(response.status_code, status.HTTP_200_OK, "Second request failed.")
