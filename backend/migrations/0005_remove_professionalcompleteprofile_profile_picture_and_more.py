# Generated by Django 5.1.4 on 2025-02-01 06:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0004_remove_professionalprofile_certifications_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='professionalcompleteprofile',
            name='profile_picture',
        ),
        migrations.AddField(
            model_name='professionalcompleteprofile',
            name='certification_file',
            field=models.FileField(blank=True, null=True, upload_to='certifications/'),
        ),
        migrations.AddField(
            model_name='professionalcompleteprofile',
            name='diploma_file',
            field=models.FileField(blank=True, null=True, upload_to='diplomas/'),
        ),
    ]
