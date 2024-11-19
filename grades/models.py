from django.db import models
from users.models import User
from courses.models import Course


class Grade(models.Model):
    student_id = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'role': 'student'}, related_name='grades')
    course_id = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='grades')
    grade = models.CharField(max_length=5)
    date = models.DateField(auto_now_add=True)
    teacher_id = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'role': 'teacher'}, related_name='assigned_grades')

    def __str__(self):
        return f"{self.student_id.username} - {self.course_id.name} - {self.grade}"

    class Meta:
        ordering = ['id']
