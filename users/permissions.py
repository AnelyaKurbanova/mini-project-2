from rest_framework import permissions
from rest_framework.permissions import SAFE_METHODS, BasePermission


class IsTeacher(permissions.BasePermission):
    """
    Permission for teachers.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'teacher'


class IsTeacherOrReadOnly(permissions.BasePermission):
    """
    Преподаватели могут изменять данные, остальные только читать.
    """
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user.is_authenticated and request.user.role == 'teacher'


class IsCourseOwner(permissions.BasePermission):
    """
    Teachers can change the data, the rest can only read.
    """
    def has_object_permission(self, request, view, obj):
        return request.user.is_authenticated and obj.teacher == request.user


class IsAdmin(permissions.BasePermission):
    """
    Full access for administrators.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'

class IsStudentOrTeacher(BasePermission):
    """
    Custom permission:
    - Students can view their own grades (GET).
    - Teachers and admins can manage grades (GET, PUT, DELETE).
    """
    def has_object_permission(self, request, view, obj):
        user = request.user

        # Allow students to view their grades
        if user.role == 'student' and request.method in SAFE_METHODS:
            return obj.student_id == user

        # Allow teachers to manage their assigned grades
        if user.role == 'teacher':
            return obj.teacher_id == user

        # Allow admins full access
        if user.role == 'admin':
            return True

        return False