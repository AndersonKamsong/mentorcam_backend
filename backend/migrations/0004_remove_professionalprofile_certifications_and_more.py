# Generated by Django 5.1.4 on 2025-01-31 15:01

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0003_customuser_location'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='professionalprofile',
            name='certifications',
        ),
        migrations.RemoveField(
            model_name='professionalprofile',
            name='domains',
        ),
        migrations.RemoveField(
            model_name='professionalprofile',
            name='educations',
        ),
        migrations.RemoveField(
            model_name='professionalprofile',
            name='mentorship_plans',
        ),
        migrations.RemoveField(
            model_name='professionalprofile',
            name='user',
        ),
        migrations.CreateModel(
            name='ProfessionalCompleteProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(blank=True, max_length=255, null=True)),
                ('biography', models.TextField(blank=True, null=True)),
                ('hourly_rate', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('profile_picture', models.ImageField(blank=True, null=True, upload_to='profile_pictures/')),
                ('linkedin', models.URLField(blank=True, null=True)),
                ('github', models.URLField(blank=True, null=True)),
                ('twitter', models.URLField(blank=True, null=True)),
                ('website', models.URLField(blank=True, null=True)),
                ('degree', models.CharField(blank=True, max_length=255, null=True)),
                ('institution', models.CharField(blank=True, max_length=255, null=True)),
                ('education_year', models.CharField(blank=True, max_length=4, null=True)),
                ('certification_name', models.CharField(blank=True, max_length=255, null=True)),
                ('certification_issuer', models.CharField(blank=True, max_length=255, null=True)),
                ('certification_year', models.CharField(blank=True, max_length=4, null=True)),
                ('plan_type', models.CharField(blank=True, choices=[('monthly', 'Monthly'), ('trimester', 'Trimester'), ('yearly', 'Yearly')], max_length=20, null=True)),
                ('plan_price', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('plan_description', models.TextField(blank=True, null=True)),
                ('max_students', models.PositiveIntegerField(blank=True, null=True)),
                ('domain_name', models.CharField(blank=True, max_length=255, null=True)),
                ('subdomains', models.JSONField(blank=True, default=list, null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='professional_complete_profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.DeleteModel(
            name='Certification',
        ),
        migrations.DeleteModel(
            name='Domain',
        ),
        migrations.DeleteModel(
            name='Education',
        ),
        migrations.DeleteModel(
            name='MentorshipPlan',
        ),
        migrations.DeleteModel(
            name='ProfessionalProfile',
        ),
    ]
