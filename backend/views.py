# Standard library imports
import logging
import os
import random
import uuid
from datetime import timedelta

# Third-party library imports
import yagmail
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, logout
from django.contrib.auth.password_validation import validate_password
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.mail import send_mail
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.http import FileResponse, HttpResponse
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend

# Django REST framework imports
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

# JWT authentication imports
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken

# Local application imports
from .models import (
    Booking,
    CustomUser,
    Event,
    EventAttendee,
    EventTag,
    Job,
    JobApplication,
    ProfessionalCompleteProfile,
    ProfessionalRating,
)
from .serializers import (
    BookingSerializer,
    ContactSerializer,
    EventAttendeeSerializer,
    EventAttendeeWithUserDetailsSerializer,
    EventSerializer,
    EventTagSerializer,
    JobApplicationSerializer,
    JobSerializer,
    NewsletterSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    ProfessionalCompleteProfileSerializer,
    ProfessionalListSerializer,
    PublicMentorSearchSerializer,
    RatingSerializer,
    RegisterSerializer,
    UserSerializer,
    VerifyResetCodeSerializer,
)
from .utils import generate_pdf_receipt

# External SDK imports
from campay.sdk import Client as CamPayClient

# Logging configuration
from venv import logger


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


logger = logging.getLogger(__name__)

class BookingViewSet(viewsets.ModelViewSet):
    serializer_class = BookingSerializer
    permission_classes = [IsAuthenticated]
    
    campay = CamPayClient({
        "app_username": settings.CAMPAY_USERNAME,
        "app_password": settings.CAMPAY_PASSWORD,
        "environment": "PROD"
    })

    def get_queryset(self):
        user = self.request.user
        if user.user_type == 'professional' and hasattr(user, 'professional_complete_profile'):
            # Return bookings where the mentor profile belongs to the logged-in professional user
            return Booking.objects.filter(mentor=user.professional_complete_profile)
        elif user.user_type == 'amateur':
            # Return bookings made by the amateur user
            return Booking.objects.filter(student=user)
        return Booking.objects.none()  # Return empty queryset for other user types

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        try:
            data = request.data.copy()  # Create a mutable copy
            logger.info(f"Received booking data: {data}")
            
            # Convert mentorId to mentor for serializer compatibility
            if 'mentorId' in data:
                data['mentor'] = data.pop('mentorId')
            
            # Validate required fields
            required_fields = ['mentor', 'studentName', 'studentEmail', 'mentorName', 
                             'phoneNumber', 'amount', 'planType', 'domain', 'subdomains']
            
            missing_fields = [field for field in required_fields if not data.get(field)]
            if missing_fields:
                return Response({
                    'error': f'Missing required fields: {", ".join(missing_fields)}'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check if user already has an active booking
            existing_booking = Booking.objects.filter(
                student=request.user,
                mentor_id=data['mentor'],
                status__in=['pending', 'confirmed']
            ).first()

            if existing_booking:
                return Response({
                    'error': 'You already have an ongoing session with this mentor',
                    'booking_id': existing_booking.id
                }, status=status.HTTP_400_BAD_REQUEST)

            # Format phone number
            phone = data.get('phoneNumber', '')
            if not phone.startswith('237'):
                phone = '237' + phone

            # Generate payment reference
            payment_reference = str(uuid.uuid4())

            # Initialize CamPay payment
            payment_response = self.campay.collect({
                "amount": str(data['amount']),
                "currency": "XAF",
                "from": phone,
                "description": f"Booking with {data['mentorName']}",
                "external_reference": payment_reference
            })

            logger.info(f"Payment response: {payment_response}")


            if payment_response.get('status') == 'SUCCESSFUL':
                # Prepare booking data
                booking_data = {
                    'mentor': data['mentor'],
                    'student_name': data['studentName'],
                    'student_email': data['studentEmail'],
                    'mentor_name': data['mentorName'],
                    'phone_number': phone,
                    'amount': data['amount'],
                    'transaction_id': payment_response['reference'],
                    'plan_type': data['planType'],
                    'domain': data['domain'],
                    'subdomains': data['subdomains'],
                    'status': 'confirmed',
                    'payment_reference': payment_response.get('external_reference')
                }

                logger.info(f"Creating booking with data: {booking_data}")
                
                serializer = self.get_serializer(data=booking_data)
                
                if serializer.is_valid():
                    booking = serializer.save(student=request.user)
                    
                    # Generate PDF receipt
                    file_name, pdf_file = generate_pdf_receipt(booking)
                    booking.pdf_receipt.save(file_name, pdf_file)

                    return Response({
                        'status': 'success',
                        'booking': serializer.data,
                        'receipt_url': booking.pdf_receipt.url if booking.pdf_receipt else None
                    }, status=status.HTTP_201_CREATED)
                
                logger.error(f"Serializer errors: {serializer.errors}")
                return Response({
                    'error': 'Invalid booking data',
                    'details': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({
                'error': 'Payment failed',
                'details': payment_response.get('message', 'Unknown error')
            }, status=status.HTTP_400_BAD_REQUEST)

        except IntegrityError as e:
            logger.error(f"IntegrityError: {str(e)}")
            return Response({
                'error': 'You already have an ongoing session with this mentor'
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return Response({
                'error': 'Booking creation failed',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['get'], url_path='check-active/(?P<mentor_id>[^/.]+)')
    def check_active_booking(self, request, mentor_id=None):
        try:
            active_booking = Booking.objects.filter(
                student=request.user,
                mentor_id=mentor_id,
                status__in=['pending', 'confirmed']
            ).exists()
            
            return Response({
                'hasActiveBooking': active_booking
            })
        except Exception as e:
            logger.error(f"Error checking active booking: {str(e)}")
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['get'], url_path='receipt')
    def download_receipt(self, request, pk=None):
        booking = self.get_object()
        if not booking.pdf_receipt:
            return Response({'error': 'No receipt available'}, status=status.HTTP_404_NOT_FOUND)
        
        file_path = booking.pdf_receipt.path
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                response = HttpResponse(f, content_type='application/pdf')
                response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
                return response
        return Response({'error': 'Receipt file not found'}, status=status.HTTP_404_NOT_FOUND)
        

class EventViewSet(viewsets.ModelViewSet):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['status', 'is_virtual', 'is_featured']
    search_fields = ['title', 'description', 'location']

    @action(detail=False, methods=['get'])
    def stats(self, request):
        total_events = Event.objects.count()
        total_attendees = sum(Event.objects.values_list('attendees_count', flat=True))
        virtual_events = Event.objects.filter(is_virtual=True).count()
        completed_events = Event.objects.filter(status='ended').count()

        return Response({
            'total_events': total_events,
            'total_attendees': total_attendees,
            'virtual_events': virtual_events,
            'completed_events': completed_events
        })

    @action(detail=True, methods=['post'])
    def register(self, request, pk=None):
        event = self.get_object()
        user = request.user
        
        if event.register_attendee(user):
            return Response({'status': 'registered'})
        return Response(
            {'error': 'Registration failed - event might be full'},
            status=status.HTTP_400_BAD_REQUEST
        )

    @action(detail=True, methods=['post'])
    def add_tag(self, request, pk=None):
        event = self.get_object()
        tag_name = request.data.get('name')
        
        if not tag_name:
            return Response(
                {'error': 'Tag name is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        tag, created = EventTag.objects.get_or_create(name=tag_name)
        event.tags.add(tag)
        
        return Response(EventTagSerializer(tag).data)

    @action(detail=True, methods=['get'])
    def attendees(self, request, pk=None):
        event = self.get_object()
        attendees = event.attendees.all()
        
        # Check if we should include detailed user information
        include_user_details = request.query_params.get('include_user_details', 'false') == 'true'
        
        if include_user_details:
            serializer = EventAttendeeWithUserDetailsSerializer(attendees, many=True)
        else:
            serializer = EventAttendeeSerializer(attendees, many=True)
        
        return Response(serializer.data)

    @action(detail=True, methods=['patch'])
    def update_attendee_status(self, request, pk=None):
        event = self.get_object()
        user_id = request.data.get('user_id')
        status = request.data.get('status')
        
        try:
            attendee = event.attendees.get(user_id=user_id)
            attendee.attendance_status = status
            attendee.save()
            return Response(EventAttendeeSerializer(attendee).data)
        except EventAttendee.DoesNotExist:
            return Response(
                {'error': 'Attendee not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        

class JobViewSet(viewsets.ModelViewSet):
    serializer_class = JobSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['type', 'location', 'is_active']
    search_fields = ['title', 'company', 'location', 'description']

    def get_queryset(self):
        return Job.objects.filter(is_active=True).order_by('-posted_date')

    def perform_create(self, serializer):
        serializer.save(posted_by=self.request.user)

    @action(detail=True, methods=['post'])
    def apply(self, request, pk=None):
        job = self.get_object()
        
        # Check if already applied
        existing_application = JobApplication.objects.filter(
            job=job,
            applicant=request.user
        ).first()
        
        if existing_application:
            return Response(
                {'error': 'Already applied for this job'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create application
        application = JobApplication.objects.create(
            job=job,
            applicant=request.user,
            cover_letter=request.data.get('cover_letter', ''),
            resume=request.data.get('resume')
        )
        
        serializer = JobApplicationSerializer(application)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['get'])
    def applicants(self, request, pk=None):
        job = self.get_object()
        applications = job.applications.all().select_related('applicant')
        data = []
        
        for application in applications:
            applicant = application.applicant
            data.append({
                'id': application.id,
                'job_id': job.id,
                'status': application.status,
                'applied_date': application.applied_date,
                'cover_letter': application.cover_letter,
                'resume': request.build_absolute_uri(application.resume.url) if application.resume else None,
                'applicant': {
                    'id': applicant.id,
                    'full_name': applicant.full_name,
                    'email': applicant.email,
                    'location': applicant.location,
                    'phone_number': applicant.phone_number
                }
            })
        
        return Response(data)

    @action(detail=False, methods=['get'])
    def applications(self, request):
        """Get all applications with job and applicant details"""
        applications = JobApplication.objects.select_related(
            'job', 
            'applicant'
        ).all().order_by('-applied_date')
        
        data = []
        for application in applications:
            data.append({
                'id': application.id,
                'job': {
                    'id': application.job.id,
                    'title': application.job.title,
                    'company': application.job.company,
                    'type': application.job.type,
                },
                'applicant': {
                    'id': application.applicant.id,
                    'full_name': application.applicant.full_name,
                    'email': application.applicant.email,
                    'location': application.applicant.location,
                    'phone_number': application.applicant.phone_number
                },
                'status': application.status,
                'applied_date': application.applied_date,
                'resume': request.build_absolute_uri(application.resume.url) if application.resume else None,
                'cover_letter': application.cover_letter
            })
        
        return Response(data)

    @action(detail=True, methods=['post'])
    def send_email(self, request, pk=None):
        try:
            email = request.data.get('email')
            subject = request.data.get('subject')
            message = request.data.get('message')
            
            if not all([email, subject, message]):
                return Response(
                    {'error': 'Email, subject, and message are required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                # First try using yagmail
                username = "yvangodimomo@gmail.com"
                password = "pzls apph esje cgdl"
                yag = yagmail.SMTP(username, password)
                
                # Send email
                yag.send(
                    to=email,
                    subject=subject,
                    contents=message
                )
            except:
                # Fallback to Django's send_mail
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )
            
            return Response({'status': 'email sent'})
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['patch'])
    def update_application(self, request, pk=None):
        try:
            application_id = request.data.get('application_id')
            new_status = request.data.get('status')
            
            if not all([application_id, new_status]):
                return Response(
                    {'error': 'Application ID and status are required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            application = JobApplication.objects.get(id=application_id, job_id=pk)
            application.status = new_status
            application.save()
            
            return Response({'status': 'updated'})
        except JobApplication.DoesNotExist:
            return Response(
                {'error': 'Application not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        