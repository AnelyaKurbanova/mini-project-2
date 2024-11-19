from django.core.cache import cache
from rest_framework import generics, permissions
from rest_framework.response import Response

from .models import Student
from .serializers import StudentSerializer
from users.permissions import IsAdmin

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import OrderingFilter, SearchFilter

import logging
logger = logging.getLogger(__name__)


class StudentListView(generics.ListCreateAPIView):
    """
        get:
        Retrieve a list of all students. Only accessible to admins.

        post:
        Add a new student.

        Request body:
        - `user`: The ID of the associated user.
        - `dob`: The date of birth of the student.
        - `registration_date`: The registration date.

        Response:
        - List of students with their details or the created student object.
        """
    queryset = Student.objects.all()
    serializer_class = StudentSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdmin]
    filter_backends = [DjangoFilterBackend, OrderingFilter, SearchFilter]
    filterset_fields = ['registration_date']
    search_fields = ['name', 'email']
    ordering_fields = ['name', 'id']


class StudentDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
        get:
        Retrieve the details of a specific student.

        put:
        Update the details of a specific student.

        delete:
        Delete a student by their ID.

        Parameters:
        - `id`: The ID of the student.

        Response:
        - The updated or retrieved student details.
        """
    queryset = Student.objects.all()
    serializer_class = StudentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def retrieve(self, request, *args, **kwargs):
        student_id = kwargs.get('pk')
        cache_key = f'student_profile_{student_id}'
        cached_data = cache.get(cache_key)

        if cached_data:
            logger.info(f"Данные из кэша для студента {student_id}")
            return Response(cached_data)

        logger.info(f"Кэш отсутствует. Загружаем из базы для студента {student_id}")
        response = super().retrieve(request, *args, **kwargs)
        cache.set(cache_key, response.data, timeout=300)
        return response
    def update(self, request, *args, **kwargs):
        student_id = kwargs.get('pk')
        cache_key = f'student_profile_{student_id}'
        cache.delete(cache_key)

        return super().update(request, *args, **kwargs)
