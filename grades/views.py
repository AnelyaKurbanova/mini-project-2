from rest_framework import generics, permissions

from analytics.utils import send_event_to_google_analytics
from .models import Grade
from .serializers import GradeSerializer
from users.permissions import IsTeacher, IsAdmin, IsStudentOrTeacher

import logging


logger = logging.getLogger('custom')
class BaseGradeView:
    """
    Base class for filtering grades based on user role.
    """
    def get_queryset_by_role(self):
        user = self.request.user
        if user.role == 'student':
            return Grade.objects.filter(student_id=user)
        elif user.role == 'teacher':
            return Grade.objects.filter(teacher_id=user)
        elif user.role == 'admin':
            return Grade.objects.all()
        return Grade.objects.none()


class GradeListView(BaseGradeView, generics.ListCreateAPIView):
    """
        get:
        Retrieve a list of all grades for the authenticated user.

        post:
        Add a new grade. Only accessible to teachers.

        Request body:
        - `student_id`: The ID of the student.
        - `course_id`: The ID of the course.
        - `grade`: The grade to assign.

        Response:
        - List of grades or the created grade object.
        """
    serializer_class = GradeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return self.get_queryset_by_role()

    def list(self, request, *args, **kwargs):
        send_event_to_google_analytics('Grades', 'List', request.user.username)
        return super().list(request, *args, **kwargs)


class GradeDetailView(BaseGradeView, generics.RetrieveUpdateDestroyAPIView):
    """
        get:
        Retrieve the details of a specific grade.

        put:
        Update a specific grade. Only accessible to teachers or admins.

        delete:
        Delete a grade. Only accessible to teachers or admins.

        Parameters:
        - `id`: The ID of the grade.

        Response:
        - The updated or retrieved grade details.
        """
    serializer_class = GradeSerializer
    permission_classes = [permissions.IsAuthenticated, IsStudentOrTeacher]

    def get_queryset(self):
        return self.get_queryset_by_role()
