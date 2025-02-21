# Generated by Django 5.1.4 on 2025-02-10 08:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0010_remove_booking_backend_boo_mentor__03adb7_idx_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='booking',
            name='student_email',
            field=models.EmailField(default='null', max_length=255),
        ),
        migrations.AlterField(
            model_name='booking',
            name='student_name',
            field=models.CharField(default='null', max_length=255),
        ),
        migrations.AddConstraint(
            model_name='booking',
            constraint=models.UniqueConstraint(condition=models.Q(('status__in', ['pending', 'confirmed'])), fields=('student', 'mentor'), name='unique_active_booking'),
        ),
    ]
