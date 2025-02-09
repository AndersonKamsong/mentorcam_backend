this models(from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.conf import settings


class CustomUser(AbstractUser):
    USER_TYPES = (
        ('amateur', 'Amateur'),
        ('professional', 'Professional'),
        ('institution', 'Institution'),
        ('admin', 'Admin'),
    )
    
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=20)
    user_type = models.CharField(max_length=20, choices=USER_TYPES, default='amateur')
    last_logout = models.DateTimeField(null=True, blank=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', null=True, blank=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'full_name']

def record_logout(self):
    self.last_logout = timezone.now()
    self.save(update_fields=['last_logout'])


class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return f"{self.name} - {self.subject}"

class Newsletter(models.Model):
    email = models.EmailField(unique=True)
    subscribed_at = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return self.email


from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class ProfessionalCompleteProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='professional_complete_profile')
    title = models.CharField(max_length=255, blank=True, null=True)
    biography = models.TextField(blank=True, null=True)
    hourly_rate = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    linkedin = models.URLField(blank=True, null=True)
    github = models.URLField(blank=True, null=True)
    twitter = models.URLField(blank=True, null=True)
    website = models.URLField(blank=True, null=True)
    
    # Education Fields
    degree = models.CharField(max_length=255, blank=True, null=True)
    institution = models.CharField(max_length=255, blank=True, null=True)
    education_year = models.CharField(max_length=4, blank=True, null=True)
    
    # Certification Fields
    certification_name = models.CharField(max_length=255, blank=True, null=True)
    certification_issuer = models.CharField(max_length=255, blank=True, null=True)
    certification_year = models.CharField(max_length=4, blank=True, null=True)
    certification_file = models.FileField(upload_to='certifications/', blank=True, null=True)
    diploma_file = models.FileField(upload_to='diplomas/', blank=True, null=True)
    
    # Mentorship Plan Fields
    PLAN_CHOICES = [
        ('monthly', 'Monthly'),
        ('trimester', 'Trimester'),
        ('semester', 'Semester'),
        ('yearly', 'Yearly'),
        ('annually', 'Annually'),
    ]
    plan_type = models.CharField(max_length=20, choices=PLAN_CHOICES, blank=True, null=True)
    plan_price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    plan_description = models.TextField(blank=True, null=True)
    max_students = models.PositiveIntegerField(blank=True, null=True)
    
    # Domain Fields
    domain_name = models.CharField(max_length=255, blank=True, null=True)
    subdomains = models.JSONField(default=list, blank=True, null=True)
    
    # Price Tracking Field
    price_traffic = models.PositiveIntegerField(default=0, help_text="Track the number of views or changes on pricing")
    
    def __str__(self):
        return f"{self.user.username}'s Complete Professional Profile"


from django.core.validators import MinValueValidator, MaxValueValidator

class ProfessionalRating(models.Model):
    professional = models.ForeignKey('ProfessionalCompleteProfile', on_delete=models.CASCADE, related_name='ratings')
    rated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='ratings_given')
    rating = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])
    comment = models.TextField()
    experience_details = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    domain = models.CharField(max_length=255)
    subdomain = models.CharField(max_length=255)

    class Meta:
        unique_together = ('professional', 'rated_by')

class Booking(models.Model):
    mentor = models.ForeignKey('ProfessionalCompleteProfile', on_delete=models.CASCADE)
    student = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    booking_date = models.DateTimeField(auto_now_add=True)
    session_date = models.DateTimeField()
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('confirmed', 'Confirmed'),
            ('completed', 'Completed'),
            ('cancelled', 'Cancelled')
        ],
        default='pending'
    )
    phone_number = models.CharField(max_length=15)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_id = models.CharField(max_length=100)

    class Meta:
        ordering = ['-booking_date']
)

serailizer(
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
        read_only_fields = ('student', 'status')
)

urls(path('mentors/search/', PublicProfessionalProfileSearchView.as_view(), name='public-mentor-search'),

    path('professional-profile/', ProfessionalCompleteProfileView.as_view(), name='professional-profile'),
    path('professional-profile/<int:profile_id>/upload/', FileUploadView.as_view(), name='professional-profile-upload'),
    
    
    path('professionals/', views.list_professionals, name='list-professionals'),
)

and view(
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_current_user(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

class UpdateUserView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Email configuration
username = "yvangodimomo@gmail.com"
password = "pzls apph esje cgdl"
yag = yagmail.SMTP(username, password)

def generate_reset_code():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

@api_view(['POST'])
@permission_classes([AllowAny])
def request_password_reset(request):
    try:
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            # Check if user exists
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                return Response(
                    {'error': 'No account found with this email'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Generate and store reset code
            reset_code = generate_reset_code()
            cache_key = f'password_reset_{email}'
            cache.set(cache_key, reset_code, timeout=300)  # 5 minutes expiry
            
            # Send email
            subject = "Password Reset Code"
            contents = [
                f"Your password reset code is: {reset_code}",
                "This code will expire in 5 minutes.",
                "If you didn't request this reset, please ignore this email."
            ]
            
            yag.send(to=email, subject=subject, contents=contents)
            
            return Response({
                'message': 'Reset code sent successfully',
                'email': email
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_reset_code(request):
    try:
        serializer = VerifyResetCodeSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            submitted_code = serializer.validated_data['code']
            
            # Get stored code
            cache_key = f'password_reset_{email}'
            stored_code = cache.get(cache_key)
            
            if not stored_code:
                return Response(
                    {'error': 'Reset code has expired'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if submitted_code != stored_code:
                return Response(
                    {'error': 'Invalid reset code'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return Response({'message': 'Code verified successfully'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request):
    try:
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            submitted_code = serializer.validated_data['code']
            new_password = serializer.validated_data['new_password']
            
            # Verify code again
            cache_key = f'password_reset_{email}'
            stored_code = cache.get(cache_key)
            
            if not stored_code or submitted_code != stored_code:
                return Response(
                    {'error': 'Invalid or expired reset code'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get user and update password
            try:
                user = CustomUser.objects.get(email=email)
                validate_password(new_password, user)
                user.set_password(new_password)
                user.save()
                
                # Clear the reset code
                cache.delete(cache_key)
                
                # Send confirmation email
                subject = "Password Reset Successful"
                contents = [
                    "Your password has been successfully reset.",
                    "If you didn't make this change, please contact support immediately."
                ]
                yag.send(to=email, subject=subject, contents=contents)
                
                return Response({'message': 'Password reset successful'})
            except CustomUser.DoesNotExist:
                return Response(
                    {'error': 'User not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            except ValidationError as e:
                return Response(
                    {'error': e.messages},
                    status=status.HTTP_400_BAD_REQUEST
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    

class ContactView(APIView):
    def post(self, request):
        serializer = ContactSerializer(data=request.data)
        if serializer.is_valid():
            contact = serializer.save()
            
            # Send email notification
            send_mail(
                subject=f'New Contact Form Submission: {contact.subject}',
                message=f'Name: {contact.name}\nEmail: {contact.email}\nMessage: {contact.message}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[settings.ADMIN_EMAIL],
                fail_silently=False,
            )
            
            return Response(
                {'message': 'Message sent successfully'},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class NewsletterView(APIView):
    def post(self, request):
        serializer = NewsletterSerializer(data=request.data)
        if serializer.is_valid():
            try:
                serializer.save()
                return Response(
                    {'message': 'Successfully subscribed to newsletter'},
                    status=status.HTTP_201_CREATED
                )
            except:
                return Response(
                    {'message': 'This email is already subscribed'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

    from rest_framework import status, viewsets

class IsAdminUser(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.user_type == 'admin'

class UserViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = UserSerializer

    def list(self, request):
        """Get all users"""
        queryset = CustomUser.objects.all()
        
        # Handle search functionality
        search_term = request.query_params.get('search', '')
        if search_term:
            queryset = queryset.filter(
                Q(email__icontains=search_term) |
                Q(username__icontains=search_term) |
                Q(full_name__icontains=search_term)
            )
            
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data)

    def create(self, request):
        """Create a new user"""
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        """Get a specific user"""
        user = get_object_or_404(CustomUser, pk=pk)
        serializer = self.serializer_class(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        """Update a user"""
        user = get_object_or_404(CustomUser, pk=pk)
        serializer = self.serializer_class(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        """Delete a user"""
        user = get_object_or_404(CustomUser, pk=pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['patch'])
    def toggle_active(self, request, pk=None):
        """Toggle user active status"""
        user = get_object_or_404(CustomUser, pk=pk)
        user.is_active = not user.is_active
        user.save()
        serializer = self.serializer_class(user)
        return Response(serializer.data)
    
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        user = get_object_or_404(user, id=user_id)
        profile = get_object_or_404(ProfessionalProfile, user=user)
        serializer = ProfessionalProfileSerializer(profile)
        return Response(serializer.data)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.db.models import Q
from .models import ProfessionalCompleteProfile
from .serializers import PublicMentorSearchSerializer

class PublicProfessionalProfileSearchView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated access
    
    def get(self, request):
        search_query = request.query_params.get('domain', '').strip().lower()
        
        if not search_query:
            return Response(
                {"error": "Search query is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Search in both domain_name and subdomains
        mentors = ProfessionalCompleteProfile.objects.filter(
            Q(domain_name__icontains=search_query) |
            Q(subdomains__icontains=search_query)
        ).select_related('user')
        
        if not mentors.exists():
            return Response({
                "message": "No mentors found for the specified domain.",
                "results": []
            })
        
        serializer = PublicMentorSearchSerializer(mentors, many=True)
        
        return Response({
            "message": f"Found {mentors.count()} mentor(s) for '{search_query}'",
            "results": serializer.data,
            "requiresAuth": True  # Flag to indicate authentication is needed for full access
        })

class ProfessionalCompleteProfileView(APIView):
    serializer_class = ProfessionalCompleteProfileSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        # Handle GET request to retrieve the profile
        try:
            profile = ProfessionalCompleteProfile.objects.get(user=request.user)
            serializer = self.serializer_class(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except ProfessionalCompleteProfile.DoesNotExist:
            return Response(
                {"detail": "Profile not found"},
                status=status.HTTP_404_NOT_FOUND
            )

    def post(self, request, *args, **kwargs):
        try:
            # Log the incoming request data
            logger.info(f"Received data: {request.data}")

            if ProfessionalCompleteProfile.objects.filter(user=request.user).exists():
                return Response(
                    {"detail": "Profile already exists"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Remove file fields from request data
            data = request.data.copy()
            for field in ['certification_file', 'diploma_file']:
                if field in data:
                    del data[field]

            # Convert empty strings to None for optional fields
            for key, value in data.items():
                if value == '':
                    data[key] = None

            serializer = self.serializer_class(data=data, context={'request': request})
            
            if not serializer.is_valid():
                logger.error(f"Validation errors: {serializer.errors}")
                return Response(
                    {"errors": serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            profile = serializer.save(user=request.user)
            logger.info(f"Profile created successfully for user {request.user.id}")
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.exception("Error creating profile")
            return Response(
                {"detail": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    def put(self, request, *args, **kwargs):
        # Handle PUT request to update the profile
        try:
            profile = ProfessionalCompleteProfile.objects.get(user=request.user)
            serializer = self.serializer_class(profile, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        except ProfessionalCompleteProfile.DoesNotExist:
            return Response(
                {"detail": "Profile not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        

class FileUploadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, profile_id, *args, **kwargs):
        try:
            # Fetch the profile using the provided profile_id
            profile = ProfessionalCompleteProfile.objects.get(id=profile_id, user=request.user)
        except ProfessionalCompleteProfile.DoesNotExist:
            return Response(
                {"detail": "Profile not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Handle file uploads
        if 'certification_file' in request.FILES:
            profile.certification_file = request.FILES['certification_file']
        if 'diploma_file' in request.FILES:
            profile.diploma_file = request.FILES['diploma_file']

        profile.save()
        return Response(
            {"detail": "Files uploaded successfully"},
            status=status.HTTP_200_OK
        )

from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q
from .models import ProfessionalRating
from .serializers import RatingSerializer, ProfessionalListSerializer

@api_view(['GET'])
def list_professionals(request):
    domain = request.query_params.get('domain', '')
    subdomain = request.query_params.get('subdomain', '')
    
    queryset = ProfessionalCompleteProfile.objects.all()
    
    if domain:
        queryset = queryset.filter(domain_name=domain)
    if subdomain:
        queryset = queryset.filter(subdomains__contains=[subdomain])
    
    serializer = ProfessionalListSerializer(queryset, many=True)
    return Response(serializer.data)

class RatingViewSet(viewsets.ModelViewSet):
    serializer_class = RatingSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return ProfessionalRating.objects.filter(
            Q(professional__user=self.request.user) | 
            Q(rated_by=self.request.user)
        )
    
    def create(self, request, *args, **kwargs):
        try:
            # Validate required fields
            if not request.data.get('domain'):
                raise ValidationError({'domain': 'This field is required.'})
            if not request.data.get('subdomain'):
                raise ValidationError({'subdomain': 'This field is required.'})
            
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
            
        except ValidationError as e:
            return Response(
                e.detail,
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def perform_create(self, serializer):
        serializer.save(rated_by=self.request.user)
)