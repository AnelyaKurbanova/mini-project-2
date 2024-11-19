from rest_framework import generics, permissions
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import OrderingFilter, SearchFilter

from analytics.models import PopularCourse
from .models import Course, Enrollment
from .serializers import CourseSerializer, EnrollmentSerializer
from users.permissions import IsTeacher, IsAdmin
from django.core.cache import cache
import logging


class CourseListView(generics.ListCreateAPIView):
    """
    get:
    Retrieve a list of all courses.

    post:
    Add a new course. Only accessible to authenticated users.

    Request body:
    - `name`: The name of the course.
    - `description`: A brief description of the course.
    - `teacher_id`: The ID of the teacher assigned to the course.

    Response:
    - List of courses or the created course object.
    """
    queryset = Course.objects.all().order_by('id')
    serializer_class = CourseSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, OrderingFilter, SearchFilter]
    filterset_fields = ['teacher_id', 'created_at']
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'id']

    def get_queryset(self):
        user = self.request.user
        cache_key = f'courses_{user.id}'
        cached_data = cache.get(cache_key)
        logger = logging.getLogger('custom')

        if cached_data:
            logger.info(f"Cache hit for user {user.email} - courses")
            return Course.objects.filter(id__in=[item['id'] for item in cached_data])

        logger.info(f"Cache miss for user {user.email} - loading courses from DB")
        queryset = super().get_queryset()
        serialized_data = CourseSerializer(queryset, many=True).data
        cache.set(cache_key, serialized_data, timeout=300)
        return queryset


class CourseDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
        get:
        Retrieve the details of a specific course.

        put:
        Update the details of a specific course.

        delete:
        Delete a course by its ID.

        Parameters:
        - `id`: The ID of the course.

        Response:
        - The updated or retrieved course details.
        """
    queryset = Course.objects.all()
    serializer_class = CourseSerializer
    permission_classes = [permissions.IsAuthenticated, IsTeacher | IsAdmin]

    def perform_update(self, serializer):
        serializer.save()
        cache.delete_pattern('courses_*')

    def retrieve(self, request, *args, **kwargs):
        course = self.get_object()
        popular_course, created = PopularCourse.objects.get_or_create(course=course)
        popular_course.access_count += 1
        popular_course.save()
        return super().retrieve(request, *args, **kwargs)


class EnrollmentView(generics.CreateAPIView):
    """
        post:
        Enroll a student in a course.

        Request body:
        - `student_id`: The ID of the student enrolling.
        - `course_id`: The ID of the course.

        Response:
        - The enrollment details.
        """
    queryset = Enrollment.objects.all()
    serializer_class = EnrollmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        enrollment = serializer.save()
        logger = logging.getLogger('custom')
        logger.info(f"User {self.request.user.email} enrolled in course {enrollment.course_id.name}")
