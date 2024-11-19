from django.db import models
from users.models import User


class Student(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='student_profile')
    dob = models.DateField(verbose_name="Date of Birth", null=True, blank=True)
    registration_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return self.user.username
