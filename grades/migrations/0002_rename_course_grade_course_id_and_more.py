# Generated by Django 5.1.3 on 2024-11-17 22:50

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("grades", "0001_initial"),
    ]

    operations = [
        migrations.RenameField(
            model_name="grade",
            old_name="course",
            new_name="course_id",
        ),
        migrations.RenameField(
            model_name="grade",
            old_name="student",
            new_name="student_id",
        ),
        migrations.RenameField(
            model_name="grade",
            old_name="teacher",
            new_name="teacher_id",
        ),
    ]
