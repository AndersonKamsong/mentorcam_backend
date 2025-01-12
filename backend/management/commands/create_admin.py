from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

class Command(BaseCommand):
    help = 'Creates an admin user with all privileges'

    def handle(self, *args, **kwargs):
        User = get_user_model()

        email = 'admin@example.com'  # Replace with your preferred admin email
        password = 'admin123'       # Replace with your preferred admin password

        if User.objects.filter(email=email).exists():
            self.stdout.write(self.style.WARNING(f'User with email {email} already exists.'))
        else:
            user = User.objects.create_superuser(
                email=email,
                username='admin',
                password=password,
                full_name='Admin User',
                phone_number='1234567890',
            )
            user.user_type = 'admin'
            user.save()

            self.stdout.write(self.style.SUCCESS(f'Admin user created with email: {email}'))
