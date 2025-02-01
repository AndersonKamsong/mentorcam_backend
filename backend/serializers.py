from rest_framework import serializers
from .models import CustomUser
from .models import Contact, Newsletter
from .models import ProfessionalCompleteProfile


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'full_name', 'phone_number', 'user_type', 'profile_picture', 'location')

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

class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(min_length=6, max_length=6)
    new_password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField(min_length=8)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return data


class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ['name', 'email', 'subject', 'message']

class NewsletterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Newsletter
        fields = ['email']

class ProfessionalCompleteProfileSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(read_only=True)
    certification_file = serializers.FileField(required=False, allow_null=True)
    diploma_file = serializers.FileField(required=False, allow_null=True)
    
    class Meta:
        model = ProfessionalCompleteProfile
        fields = '__all__'
        read_only_fields = ('user',)

    def validate(self, data):
        # Required fields validation
        required_fields = ['title', 'biography', 'domain_name']
        for field in required_fields:
            if not data.get(field):
                raise serializers.ValidationError({field: f"{field} is required"})
        
        # Validate numeric fields
        if 'hourly_rate' in data and data['hourly_rate']:
            try:
                float(data['hourly_rate'])
            except (TypeError, ValueError):
                raise serializers.ValidationError({'hourly_rate': 'Must be a valid number'})
                
        if 'plan_price' in data and data['plan_price']:
            try:
                float(data['plan_price'])
            except (TypeError, ValueError):
                raise serializers.ValidationError({'plan_price': 'Must be a valid number'})

        # Validate URLs if provided
        url_fields = ['linkedin', 'github', 'twitter', 'website']
        for field in url_fields:
            if data.get(field) and not data[field].startswith(('http://', 'https://')):
                data[field] = f'https://{data[field]}'

        # Log the validated data for debugging
        print("Validated Data:", data)
        return data



# serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import ProfessionalCompleteProfile

class PublicMentorSearchSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='user.full_name')
    email = serializers.CharField(source='user.email')
    profile_picture = serializers.CharField(source='user.profile_picture')
    location = serializers.CharField(source='user.location')
    
    class Meta:
        model = ProfessionalCompleteProfile
        fields = [
            'id', 'full_name', 'email', 'profile_picture', 'location',
            'title', 'biography', 'domain_name', 'subdomains',
            'degree', 'institution'
        ]


from .models import ProfessionalRating, ProfessionalCompleteProfile

class ProfessionalListSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source='user.full_name')
    average_rating = serializers.SerializerMethodField()
    total_reviews = serializers.SerializerMethodField()
    
    class Meta:
        model = ProfessionalCompleteProfile
        fields = ['id', 'name', 'domain_name', 'subdomains', 'average_rating', 
                 'total_reviews', 'certification_name', 'plan_price']
    
    def get_average_rating(self, obj):
        ratings = obj.ratings.all()
        if not ratings:
            return 0
        return sum(r.rating for r in ratings) / len(ratings)
    
    def get_total_reviews(self, obj):
        return obj.ratings.count()

class RatingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProfessionalRating
        fields = ['id', 'professional', 'rating', 'comment', 
                 'experience_details', 'domain', 'subdomain']
        read_only_fields = ['rated_by']
