from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import authenticate
from .serializers import ProfessionalProfileSerializer, RegisterSerializer, UserSerializer
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
from .models import CustomUser, ProfessionalProfile
from rest_framework.permissions import BasePermission
from django.db.models import Q
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.core.exceptions import ObjectDoesNotExist

from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth import logout
from rest_framework_simplejwt.exceptions import TokenError
from django.shortcuts import get_object_or_404


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
    

class IsProfessional(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.user_type == 'professional'
    
import logging

logger = logging.getLogger(__name__)

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from .models import ProfessionalProfile
from .serializers import ProfessionalProfileSerializer

@api_view(['GET', 'POST', 'PUT'])
@permission_classes([IsAuthenticated])
def professional_profile(request):
    try:
        if request.method == 'GET':
            # Try to fetch the profile, or return an empty response if it doesn't exist
            profile = ProfessionalProfile.objects.filter(user=request.user).first()
            if profile:
                serializer = ProfessionalProfileSerializer(profile)
                return Response(serializer.data)
            else:
                return Response({}, status=status.HTTP_200_OK)

        elif request.method == 'POST':
            # Check if a profile already exists for the user
            if ProfessionalProfile.objects.filter(user=request.user).exists():
                return Response(
                    {'error': 'Profile already exists. Use PUT to update.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Create a new profile
            serializer = ProfessionalProfileSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(user=request.user)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'PUT':
            # Try to fetch the profile, or create a new one if it doesn't exist
            profile, created = ProfessionalProfile.objects.get_or_create(user=request.user)
            serializer = ProfessionalProfileSerializer(profile, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


    # views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import ProfessionalProfile
from .serializers import ProfessionalProfileSerializer

class ProfessionalProfileSearchView(APIView):
    def get(self, request):
        domain = request.query_params.get('domain', '').strip().lower()
        if not domain:
            return Response(
                {"error": "Domain parameter is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Search for mentors whose domains match the query
        mentors = ProfessionalProfile.objects.filter(domains__icontains=domain)
        serializer = ProfessionalProfileSerializer(mentors, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)