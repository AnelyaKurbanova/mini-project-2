from django.db import models
from django.contrib.auth import get_user_model
from courses.models import Course

User = get_user_model()


class APIRequestLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    endpoint = models.CharField(max_length=255)
    method = models.CharField(max_length=10)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.endpoint} - {self.method} - {self.timestamp}"


class PopularCourse(models.Model):
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='analytics')
    access_count = models.PositiveIntegerField(default=0)

    def __str__(self):
        return f"{self.course.name} - {self.access_count} views"
