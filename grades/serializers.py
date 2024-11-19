from rest_framework import serializers
from .models import Grade
from users.models import User
from courses.models import Course


class GradeSerializer(serializers.ModelSerializer):
    student_id = serializers.PrimaryKeyRelatedField(queryset=User.objects.filter(role='student'))
    course_id = serializers.PrimaryKeyRelatedField(queryset=Course.objects.all())
    teacher_id = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Grade
        fields = ['id', 'student_id', 'course_id', 'grade', 'date', 'teacher_id']

    def create(self, validated_data):
        request = self.context.get('request')
        if not request or not request.user or request.user.role != 'teacher':
            raise serializers.ValidationError("Only teachers can create grades.")
        validated_data['teacher_id'] = request.user
        return super().create(validated_data)

