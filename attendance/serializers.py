from rest_framework import serializers
from .models import Attendance

from rest_framework import serializers
from .models import Attendance
from users.models import User
from courses.models import Course


class BulkAttendanceSerializer(serializers.Serializer):
    course_id = serializers.PrimaryKeyRelatedField(queryset=Course.objects.all())
    date = serializers.DateField()

    def create(self, validated_data):
        course = validated_data['course_id']
        date = validated_data['date']

        students = User.objects.filter(
            enrollments__course_id=course
        )

        existing_records = Attendance.objects.filter(course_id=course, date=date)
        if existing_records.exists():
            raise serializers.ValidationError("Attendance for this course and date already exists.")

        records = [
            Attendance(student_id=student, course_id=course, date=date, status='absent')
            for student in students
        ]
        return Attendance.objects.bulk_create(records)


class AttendanceSerializer(serializers.ModelSerializer):
    student_id = serializers.PrimaryKeyRelatedField(read_only=True)
    course_id = serializers.PrimaryKeyRelatedField(read_only=True)
    date = serializers.DateField(read_only=True)

    class Meta:
        model = Attendance
        fields = ['id', 'student_id', 'course_id', 'date', 'status']


class BulkUpdateAttendanceSerializer(serializers.Serializer):
    attendance_ids = serializers.ListField(
        child=serializers.IntegerField(),
        allow_empty=False
    )
    status = serializers.ChoiceField(choices=[('present', 'Present'), ('absent', 'Absent')])

    def validate(self, data):
        invalid_ids = [
            attendance_id
            for attendance_id in data['attendance_ids']
            if not Attendance.objects.filter(id=attendance_id).exists()
        ]
        if invalid_ids:
            raise serializers.ValidationError(
                f"Attendance records with IDs {invalid_ids} do not exist."
            )
        return data

    def update(self, validated_data):
        records = Attendance.objects.filter(id__in=validated_data['attendance_ids'])
        records.update(status=validated_data['status'])
        return records