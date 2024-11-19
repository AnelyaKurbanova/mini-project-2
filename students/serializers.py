from rest_framework import serializers

from users.models import User
from .models import Student
from users.serializers import UserSerializer


class StudentSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = Student
        fields = ['id', 'user', 'dob', 'registration_date']

    def create(self, validated_data):
        user_data = validated_data.pop('user')
        user = User.objects.create(**user_data, role='student')
        student = Student.objects.create(user=user, **validated_data)
        return student

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', None)
        if user_data:
            for attr, value in user_data.items():
                setattr(instance.user, attr, value)
            instance.user.save()
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance
