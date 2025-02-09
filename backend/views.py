from venv import logger
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import authenticate
from .serializers import BookingSerializer, RegisterSerializer, UserSerializer
from django.core.exceptions import ValidationError
from django.contrib.auth import logout
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
import random
from datetime import timedelta
import yagmail
import random
from django.core.cache import cache
from rest_framework import status, viewsets
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import get_user_model
from .serializers import (
    PasswordResetRequestSerializer, 
    VerifyResetCodeSerializer, 
    PasswordResetConfirmSerializer
)

from rest_framework.views import APIView
from .serializers import ContactSerializer, NewsletterSerializer
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404
from .models import Booking, CustomUser
from rest_framework.permissions import BasePermission
from django.db.models import Q
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import logout
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework import viewsets
from .models import ProfessionalCompleteProfile
from .serializers import ProfessionalCompleteProfileSerializer
from backend import serializers



CustomUser = get_user_model()


@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    try:
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            response_data = {
                'user': UserSerializer(user).data,
                'token': str(refresh.access_token),
                'user_type': user.user_type,
                'redirect_url': f'/{user.user_type}_dashboard'
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(
            {'error': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    except ValidationError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    try:
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password:
            return Response(
                {'error': 'Please provide both email and password'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = authenticate(username=email, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            response_data = {
                'user': UserSerializer(user).data,
                'token': str(refresh.access_token),
                'user_type': user.user_type,
                'redirect_url': f'/{user.user_type}_dashboard'
            }
            return Response(response_data)
        return Response(
            {'error': 'Invalid credentials'}, 
            status=status.HTTP_401_UNAUTHORIZED
        )
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    try:
        # Get the refresh token
        refresh_token = request.data.get('refresh_token')
        
        try:
            # Record logout time - wrapped in try/except in case method fails
            if hasattr(request.user, 'record_logout'):
                request.user.record_logout()
        except Exception as e:
            print(f"Error recording logout time: {str(e)}")
            # Continue with logout even if recording fails
            pass
        
        if refresh_token:
            try:
                # Blacklist the refresh token
                token = RefreshToken(refresh_token)
                token.blacklist()
            except TokenError:
                # Continue with logout even if token blacklisting fails
                pass
        
        # Perform Django logout
        logout(request)
        
        return Response(
            {'message': 'Successfully logged out'},
            status=status.HTTP_200_OK
        )
    except Exception as e:
        print(f"Logout error: {str(e)}")  # Log the actual error
        return Response(
            {'error': 'Logout failed. Please try again.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    

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
from django.http import FileResponse
from .models import ProfessionalCompleteProfile
from .serializers import PublicMentorSearchSerializer, ProfessionalCompleteProfileSerializer

class PublicProfessionalProfileSearchView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        search_query = request.query_params.get('domain', '').strip().lower()
        
        if not search_query:
            return Response(
                {"error": "Search query is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        mentors = ProfessionalCompleteProfile.objects.filter(
            Q(domain_name__icontains=search_query) |
            Q(subdomains__icontains=search_query)
        ).select_related('user').prefetch_related('ratings')
        
        if not mentors.exists():
            return Response({
                "message": "No mentors found for the specified domain.",
                "results": []
            })
        
        serializer = PublicMentorSearchSerializer(mentors, many=True)
        
        return Response({
            "message": f"Found {mentors.count()} mentor(s) for '{search_query}'",
            "results": serializer.data
        })

class ProfessionalProfileView(APIView):
    def get(self, request, profile_id):
        try:
            profile = ProfessionalCompleteProfile.objects.get(id=profile_id)
            serializer = ProfessionalCompleteProfileSerializer(profile)
            return Response(serializer.data)
        except ProfessionalCompleteProfile.DoesNotExist:
            return Response(
                {"detail": "Profile not found"},
                status=status.HTTP_404_NOT_FOUND
            )

class PdfDocumentView(APIView):
    def get(self, request, profile_id, document_type):
        try:
            profile = ProfessionalCompleteProfile.objects.get(id=profile_id)
            
            if document_type == 'certification':
                file = profile.certification_file
            elif document_type == 'diploma':
                file = profile.diploma_file
            else:
                return Response(
                    {"detail": "Invalid document type"},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            if not file:
                return Response(
                    {"detail": "Document not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
                
            response = FileResponse(file.open(), content_type='application/pdf')
            response['Content-Disposition'] = f'inline; filename="{file.name}"'
            return response
            
        except ProfessionalCompleteProfile.DoesNotExist:
            return Response(
                {"detail": "Profile not found"},
                status=status.HTTP_404_NOT_FOUND
            )

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


class BookingViewSet(viewsets.ModelViewSet):
    serializer_class = BookingSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.user_type == 'professional':
            return Booking.objects.filter(mentor__user=user)
        return Booking.objects.filter(student=user)

    def perform_create(self, serializer):
        serializer.save(student=self.request.user)