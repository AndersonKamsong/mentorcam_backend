from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

class Command(BaseCommand):
    help = 'Creates default users with different user types'

    def handle(self, *args, **kwargs):
        User = get_user_model()

        users_data = [
            {'email': 'admin@example.com', 'username': 'admin', 'password': 'admin123', 'full_name': 'Admin User', 'phone_number': '1234567890', 'user_type': 'admin'},
            {'email': 'amateur@example.com', 'username': 'amateur_user', 'password': 'amateur123', 'full_name': 'Amateur User', 'phone_number': '9876543210', 'user_type': 'amateur'},
            {'email': 'professional@example.com', 'username': 'pro_user', 'password': 'pro123', 'full_name': 'Professional User', 'phone_number': '1122334455', 'user_type': 'professional'},
            {'email': 'institution@example.com', 'username': 'institution_user', 'password': 'institution123', 'full_name': 'Institution User', 'phone_number': '5566778899', 'user_type': 'institution'},
        ]

        for user_data in users_data:
            if User.objects.filter(email=user_data['email']).exists():
                self.stdout.write(self.style.WARNING(f"User with email {user_data['email']} already exists."))
            else:
                if user_data['user_type'] == 'admin':
                    user = User.objects.create_superuser(
                        email=user_data['email'],
                        username=user_data['username'],
                        password=user_data['password'],
                        full_name=user_data['full_name'],
                        phone_number=user_data['phone_number'],
                    )
                else:
                    user = User.objects.create_user(
                        email=user_data['email'],
                        username=user_data['username'],
                        password=user_data['password'],
                        full_name=user_data['full_name'],
                        phone_number=user_data['phone_number'],
                        user_type=user_data['user_type'],
                    )

                user.save()
                self.stdout.write(self.style.SUCCESS(f"{user_data['user_type'].capitalize()} user created with email: {user_data['email']}"))
