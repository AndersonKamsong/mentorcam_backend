from rest_framework import serializers
from .models import Certification, CustomUser, Domain, Education, MentorshipPlan, ProfessionalProfile
from .models import Contact, Newsletter


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

from rest_framework import serializers

class DomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domain
        exclude = ('profile',)

class EducationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Education
        exclude = ('profile',)

class CertificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Certification
        exclude = ('profile',)

class MentorshipPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = MentorshipPlan
        exclude = ('profile',)
class ProfessionalProfileSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='user.full_name', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    phone_number = serializers.CharField(source='user.phone_number', read_only=True)

    domains = DomainSerializer(many=True, required=False)
    education = EducationSerializer(many=True, required=False)
    certifications = CertificationSerializer(many=True, required=False)
    mentorship_plans = MentorshipPlanSerializer(many=True, required=False)

    class Meta:
        model = ProfessionalProfile
        fields = [
            'id', 'full_name', 'email', 'phone_number', 'title', 'biography', 'hourly_rate', 'location',
            'profile_picture', 'linkedin', 'github', 'twitter', 'website', 'domains', 'education',
            'certifications', 'mentorship_plans', 'created_at', 'updated_at'
        ]

    def create(self, validated_data):
        domains_data = validated_data.pop('domains', [])
        education_data = validated_data.pop('education', [])
        certifications_data = validated_data.pop('certifications', [])
        mentorship_plans_data = validated_data.pop('mentorship_plans', [])

        # Get the current user from the context
        user = self.context['request'].user
        profile = ProfessionalProfile.objects.create(user=user, **validated_data)

        # Create nested objects
        for domain_data in domains_data:
            Domain.objects.create(profile=profile, **domain_data)
        
        for edu_data in education_data:
            Education.objects.create(profile=profile, **edu_data)
        
        for cert_data in certifications_data:
            Certification.objects.create(profile=profile, **cert_data)
        
        for plan_data in mentorship_plans_data:
            MentorshipPlan.objects.create(profile=profile, **plan_data)

        return profile

    def update(self, instance, validated_data):
        # Handle nested updates
        domains_data = validated_data.pop('domains', None)
        education_data = validated_data.pop('education', None)
        certifications_data = validated_data.pop('certifications', None)
        mentorship_plans_data = validated_data.pop('mentorship_plans', None)

        # Update main profile fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Update nested objects
        if domains_data is not None:
            instance.domains.all().delete()
            for domain_data in domains_data:
                Domain.objects.create(profile=instance, **domain_data)

        if education_data is not None:
            instance.education.all().delete()
            for edu_data in education_data:
                Education.objects.create(profile=instance, **edu_data)

        if certifications_data is not None:
            instance.certifications.all().delete()
            for cert_data in certifications_data:
                Certification.objects.create(profile=instance, **cert_data)

        if mentorship_plans_data is not None:
            instance.mentorship_plans.all().delete()
            for plan_data in mentorship_plans_data:
                MentorshipPlan.objects.create(profile=instance, **plan_data)

        return instance