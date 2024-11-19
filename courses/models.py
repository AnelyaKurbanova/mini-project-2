from django.db import models
from users.models import User


class Course(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    teacher_id = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'role': 'teacher'}, related_name='courses')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Course ID: {self.id}, Name: {self.name}, Teacher: {self.teacher_id.username}"

    class Meta:
        ordering = ['id']


class Enrollment(models.Model):
    student_id = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'role': 'student'}, related_name='enrollments')
    course_id = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='enrollments')
    enrollment_date = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('student_id', 'course_id')

    def __str__(self):
        return f"Enrollment ID: {self.id}, Student: {self.student_id.username}, Course: {self.course_id.name}"
