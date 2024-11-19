from rest_framework import serializers

from students.models import Student
from users.models import User
from .models import Course, Enrollment


class CourseSerializer(serializers.ModelSerializer):
    """
        Serializer for courses.

        Fields:
        - `id`: Course ID (read-only)
        - `name`: Name of the course
        - `description`: Description of the course
        - `teacher_id`: Teacher assigned to the course
        - `created_at`: Timestamp when the course was created
    """
    teacher_id = serializers.PrimaryKeyRelatedField(queryset=User.objects.filter(role='teacher'))

    class Meta:
        model = Course
        fields = ['id', 'name', 'description', 'teacher_id', 'created_at']


class EnrollmentSerializer(serializers.ModelSerializer):
    course_id = serializers.PrimaryKeyRelatedField(queryset=Course.objects.all())
    student_id = serializers.PrimaryKeyRelatedField(queryset=Student.objects.all())

    class Meta:
        model = Enrollment
        fields = ['id', 'course_id', 'student_id', 'enrollment_date']
        read_only_fields = ['student_id', 'enrollment_date']

    def create(self, validated_data):
        request = self.context.get('request')
        if not request:
            raise serializers.ValidationError("Request context is missing.")

        student = request.user
        course = validated_data['course_id']

        if Enrollment.objects.filter(student_id=student, course_id=course).exists():
            raise serializers.ValidationError("You are already enrolled in this course.")

        validated_data['student_id'] = student
        return super().create(validated_data)
