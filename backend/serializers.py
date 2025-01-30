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


class DomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domain
        exclude = ('profile', 'id')

class EducationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Education
        exclude = ('profile', 'id')

class CertificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Certification
        exclude = ('profile', 'id')

class MentorshipPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = MentorshipPlan
        exclude = ('profile', 'id')

class ProfessionalProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    domains = DomainSerializer(many=True, read_only=True)
    education = EducationSerializer(many=True, read_only=True)
    certifications = CertificationSerializer(many=True, read_only=True)
    mentorship_plans = MentorshipPlanSerializer(many=True, read_only=True)
    profile_picture = serializers.ImageField(required=False)

    class Meta:
        model = ProfessionalProfile
        fields = '__all__'

    def create(self, validated_data):
        domains_data = self.context['request'].data.get('domains', [])
        education_data = self.context['request'].data.get('education', [])
        certifications_data = self.context['request'].data.get('certifications', [])
        mentorship_plans_data = self.context['request'].data.get('mentorship_plans', [])

        # Create professional profile
        profile = ProfessionalProfile.objects.create(**validated_data)

        # Create related objects
        self._create_related_objects(profile, domains_data, education_data, 
                                   certifications_data, mentorship_plans_data)

        return profile

    def update(self, instance, validated_data):
        domains_data = self.context['request'].data.get('domains', [])
        education_data = self.context['request'].data.get('education', [])
        certifications_data = self.context['request'].data.get('certifications', [])
        mentorship_plans_data = self.context['request'].data.get('mentorship_plans', [])

        # Update profile fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Clear existing related objects
        instance.domains.all().delete()
        instance.education.all().delete()
        instance.certifications.all().delete()
        instance.mentorship_plans.all().delete()

        # Create new related objects
        self._create_related_objects(instance, domains_data, education_data, 
                                   certifications_data, mentorship_plans_data)

        return instance

    def _create_related_objects(self, profile, domains_data, education_data, 
                              certifications_data, mentorship_plans_data):
        # Create domains
        for domain_data in domains_data:
            Domain.objects.create(profile=profile, **domain_data)

        # Create education
        for edu_data in education_data:
            Education.objects.create(profile=profile, **edu_data)

        # Create certifications
        for cert_data in certifications_data:
            Certification.objects.create