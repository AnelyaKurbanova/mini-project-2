from celery import shared_task
from django.core.mail import send_mail
from django.utils.timezone import now
from users.models import User
from grades.models import Grade
from attendance.models import Attendance


@shared_task
def send_daily_attendance_reminder():
    students = User.objects.filter(role='student')
    for student in students:
        send_mail(
            subject='Daily Attendance Reminder',
            message='Please mark your attendance for today.',
            from_email='admin@school.com',
            recipient_list=[student.email],
        )
    return f'Reminders sent to {students.count()} students.'


@shared_task
def notify_grade_update(student_email, course_name, grade):
    send_mail(
        subject='Grade Updated',
        message=f'Your grade for {course_name} has been updated to {grade}.',
        from_email='admin@school.com',
        recipient_list=[student_email],
    )
    return f'Notification sent to {student_email} for course {course_name}.'


@shared_task
def send_daily_report():
    attendance_count = Attendance.objects.count()
    grade_count = Grade.objects.count()
    send_mail(
        subject='Daily Report',
        message=f'Daily Report:\nTotal Attendance: {attendance_count}\nTotal Grades Updated: {grade_count}',
        from_email='admin@school.com',
        recipient_list=['admin@school.com'],
    )
    return 'Daily report sent to admin.'


@shared_task
def test_task():
    print("Test task executed")
    return "Task completed"


@shared_task
def add_numbers(x, y):
    return x + y