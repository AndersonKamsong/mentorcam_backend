from rest_framework import serializers
from .models import CustomUser
from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth.password_validation import validate_password


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'full_name', 'phone_number', 'user_type')

class RegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)
    
    class Meta:
        model = CustomUser
        fields = ('email', 'password', 'password2', 'full_name', 'phone_number', 
                 'user_type', 'username')
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True},
            'full_name': {'required': True},
            'phone_number': {'required': True},
            'user_type': {'required': True},
        }
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Passwords don't match"})
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password2')
        username = validated_data.pop('username', None)
        if not username:
            username = validated_data['email']  # Use email as username if not provided
            
        user = CustomUser.objects.create_user(
            username=username,
            **validated_data
        )
        return user

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyResetCodeSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(min_length=6, max_length=6)

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(min_length=6, max_length=6)
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        # Validate password strength
        validate_password(attrs['new_password'])
        return attrs
