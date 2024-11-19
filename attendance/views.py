from rest_framework import generics, permissions, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Attendance
from .serializers import AttendanceSerializer, BulkAttendanceSerializer, BulkUpdateAttendanceSerializer
from users.permissions import IsTeacher

import logging


class BaseAttendanceView:
    """
    Base class for different roles
    """
    def get_queryset_by_role(self):
        user = self.request.user
        if user.role == 'student':
            return Attendance.objects.filter(student_id=user)
        elif user.role == 'teacher':
            return Attendance.objects.filter(teacher_id=user)
        elif user.role == 'admin':
            return Attendance.objects.all()
        return Attendance.objects.none()


class AttendanceListView(BaseAttendanceView, generics.ListCreateAPIView):
    """
        get:
        Retrieve a list of all attendance records for the authenticated user.

        post:
        Add a new attendance record. Only accessible to teachers.

        Request body:
        - `student_id`: The ID of the student.
        - `course_id`: The ID of the course.
        - `status`: Attendance status (e.g., 'Present', 'Absent').

        Response:
        - List of attendance records or the created attendance record.
        """
    queryset = Attendance.objects.all()
    serializer_class = AttendanceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return self.get_queryset_by_role()

    def perform_create(self, serializer):
        user = self.request.user
        if user.role != 'teacher':
            raise PermissionError("Only teachers can mark attendance.")
        attendance = serializer.save()
        logger = logging.getLogger('custom')
        logger.info(f"Attendance marked for student {attendance.student_id} by teacher {user.email}")


class BulkAttendanceView(APIView):
    """
        post:
        Create multiple attendance records in bulk. Only accessible to teachers.

        Request body:
        - A list of attendance records, each containing:
          - `student_id`: The ID of the student.
          - `course_id`: The ID of the course.
          - `status`: Attendance status.

        Response:
        - A confirmation message indicating the number of records created.
        """
    permission_classes = [IsAuthenticated, IsTeacher]

    def post(self, request):
        serializer = BulkAttendanceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "Attendance records created successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AttendanceDetailView(BaseAttendanceView, generics.RetrieveUpdateAPIView):
    """
        get:
        Retrieve the details of a specific attendance record.

        put:
        Update a specific attendance record.

        Parameters:
        - `id`: The ID of the attendance record.

        Response:
        - The updated or retrieved attendance details.
        """
    serializer_class = AttendanceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return self.get_queryset_by_role()

    def perform_update(self, serializer):
        user = self.request.user
        attendance = self.get_object()

        if user.role == 'student' and attendance.student_id != user:
            raise PermissionError("Students can only update their own attendance records.")

        if user.role == 'teacher' and attendance.course_id.teacher_id != user:
            raise PermissionError("Teachers can only update attendance for their own courses.")

        serializer.save()


class BulkUpdateAttendanceView(APIView):
    """
        put:
        Update multiple attendance records in bulk. Only accessible to teachers.

        Request body:
        - A list of attendance records to update, each containing:
          - `id`: The ID of the attendance record.
          - Other fields to update (e.g., `status`).

        Response:
        - A confirmation message indicating the number of records updated.
        """
    permission_classes = [permissions.IsAuthenticated, IsTeacher]

    def put(self, request):
        serializer = BulkUpdateAttendanceSerializer(data=request.data)
        if serializer.is_valid():
            updated_records = serializer.update(serializer.validated_data)
            return Response(
                {"detail": f"{len(updated_records)} attendance records updated successfully."},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
