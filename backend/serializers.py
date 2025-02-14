# Logging configuration
from venv import logger

# Django core imports
from django.contrib.auth import get_user_model

# Django REST framework imports
from rest_framework import serializers

# Local application imports
from .models import (
    Booking, 
    CustomUser, 
    Contact, 
    Newsletter, 
    ProfessionalCompleteProfile, 
    ProfessionalRating, 
    Event, 
    EventTag, 
    EventAttendee, 
    Job, 
    JobApplication
)


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

        # Validate JSONField for subdomains
        if 'subdomains' in data and data['subdomains']:
            if not isinstance(data['subdomains'], list):
                raise serializers.ValidationError({'subdomains': 'Must be a list of subdomains'})

        # Log the validated data for debugging
        print("Validated Data:", data)
        return data


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

    def validate(self, data):
        # Check if user has already rated this professional
        user = self.context['request'].user
        professional = data.get('professional')
        
        if ProfessionalRating.objects.filter(
            professional=professional,
            rated_by=user
        ).exists():
            raise serializers.ValidationError({
                "detail": "You have already rated this professional"
            })
        
        # Validate required fields
        if not data.get('rating'):
            raise serializers.ValidationError({
                "rating": "Rating is required"
            })
            
        return data


class BookingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = '__all__'
        read_only_fields = ('student', 'status', 'payment_reference', 'pdf_receipt')

    def validate(self, data):
        logger.info(f"Validating data in serializer: {data}")
        
        # Ensure mentor is provided
        if 'mentor' not in data:
            raise serializers.ValidationError({"mentor": "This field is required."})
            
        # Add any additional validation here
        if not data.get('mentor_name'):
            raise serializers.ValidationError({"mentor_name": "This field is required."})
            
        return data

    def create(self, validated_data):
        logger.info(f"Creating booking with validated data: {validated_data}")
        validated_data['student'] = self.context['request'].user
        return super().create(validated_data)
    

class EventTagSerializer(serializers.ModelSerializer):
    class Meta:
        model = EventTag
        fields = ['id', 'name']

class EventAttendeeSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.get_full_name', read_only=True)
    
    class Meta:
        model = EventAttendee
        fields = ['id', 'user', 'user_name', 'registered_at', 'attendance_status']

class EventSerializer(serializers.ModelSerializer):
    tags = EventTagSerializer(many=True, read_only=True)
    tag_ids = serializers.ListField(child=serializers.IntegerField(), write_only=True, required=False)
    attendees = EventAttendeeSerializer(many=True, read_only=True)
    registration_available = serializers.SerializerMethodField()
    
    class Meta:
        model = Event
        fields = [
            'id', 'title', 'description', 'status', 'location', 'date',
            'attendees_count', 'is_virtual', 'is_featured', 'image',
            'tags', 'tag_ids', 'created_at', 'updated_at', 'organizer',
            'max_attendees', 'registration_deadline', 'attendees',
            'registration_available'
        ]

    def get_registration_available(self, obj):
        return obj.attendees.count() < obj.max_attendees

    def create(self, validated_data):
        tag_ids = validated_data.pop('tag_ids', [])
        event = Event.objects.create(**validated_data)
        event.tags.set(EventTag.objects.filter(id__in=tag_ids))
        return event

class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ['id', 'email', 'full_name', 'phone_number', 'user_type', 'location', 'profile_picture']

class EventAttendeeWithUserDetailsSerializer(serializers.ModelSerializer):
    user = UserDetailSerializer(read_only=True)
    user_name = serializers.CharField(source='user.full_name', read_only=True)
    
    class Meta:
        model = EventAttendee
        fields = ['id', 'user', 'user_name', 'registered_at', 'attendance_status']

class JobSerializer(serializers.ModelSerializer):
    applicants_count = serializers.SerializerMethodField()
    posted_date_display = serializers.SerializerMethodField()

    class Meta:
        model = Job
        fields = ['id', 'title', 'company', 'type', 'location', 'salary', 
                 'description', 'requirements', 'skills', 'posted_date', 
                 'is_active', 'applicants_count', 'posted_date_display']
        read_only_fields = ['posted_date', 'posted_by']

    def get_applicants_count(self, obj):
        return obj.applications.count()

    def get_posted_date_display(self, obj):
        from django.utils import timezone
        from datetime import datetime, timedelta
        
        now = timezone.now()
        diff = now - obj.posted_date

        if diff < timedelta(hours=24):
            hours = diff.seconds // 3600
            return f"{hours} hours ago"
        elif diff < timedelta(days=7):
            days = diff.days
            return f"{days} days ago"
        else:
            return obj.posted_date.strftime("%B %d, %Y")

class JobApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = JobApplication
        fields = ['id', 'job', 'applicant', 'applied_date', 'status', 'resume', 'cover_letter']
        read_only_fields = ['applied_date', 'status']