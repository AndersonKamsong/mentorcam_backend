from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import authenticate
from .serializers import RegisterSerializer, UserSerializer
from django.core.exceptions import ValidationError
from django.contrib.auth import logout
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from django.core.mail import send_mail
from django.conf import settings
import random
import redis
from datetime import timedelta

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
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def logout_user(request):
    try:
        # Get the refresh token from request
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            return Response(
                {'error': 'Refresh token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Blacklist the refresh token
        token = RefreshToken(refresh_token)
        token.blacklist()
        
        # Get all outstanding tokens for the user and blacklist them
        outstanding_tokens = OutstandingToken.objects.filter(user_id=request.user.id)
        for token in outstanding_tokens:
            BlacklistedToken.objects.get_or_create(token=token)

        # Logout the user from the current session
        logout(request)
        
        return Response(
            {'message': 'Successfully logged out and invalidated all sessions'},
            status=status.HTTP_200_OK
        )
    except TokenError as e:
        return Response(
            {'error': 'Invalid or expired token'},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    

    from rest_framework import status


# Initialize Redis connection
redis_client = redis.Redis(host='localhost', port=6379, db=0)

@api_view(['POST'])
@permission_classes([AllowAny])
def request_password_reset(request):
    serializer = PasswordResetRequestSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        
        try:
            user = CustomUser.objects.get(email=email)
            
            # Generate 6-digit code
            reset_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            
            # Store code in Redis with 10-minute expiration
            redis_key = f"password_reset_{email}"
            redis_client.setex(redis_key, timedelta(minutes=10), reset_code)
            
            # Send email with reset code
            send_mail(
                'Password Reset Code',
                f'Your password reset code is: {reset_code}. This code will expire in 10 minutes.',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            
            return Response({
                'message': 'Password reset code has been sent to your email'
            }, status=status.HTTP_200_OK)
            
        except CustomUser.DoesNotExist:
            # Return success even if email doesn't exist for security
            return Response({
                'message': 'If an account exists with this email, a reset code will be sent.'
            }, status=status.HTTP_200_OK)
            
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_reset_code(request):
    serializer = VerifyResetCodeSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        submitted_code = serializer.validated_data['code']
        
        # Get code from Redis
        redis_key = f"password_reset_{email}"
        stored_code = redis_client.get(redis_key)
        
        if stored_code and stored_code.decode() == submitted_code:
            return Response({
                'message': 'Code verified successfully'
            }, status=status.HTTP_200_OK)
        
        return Response({
            'error': 'Invalid or expired code'
        }, status=status.HTTP_400_BAD_REQUEST)
        
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request):
    serializer = PasswordResetSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        submitted_code = serializer.validated_data['code']
        new_password = serializer.validated_data['new_password']
        
        # Verify code from Redis
        redis_key = f"password_reset_{email}"
        stored_code = redis_client.get(redis_key)
        
        if not stored_code or stored_code.decode() != submitted_code:
            return Response({
                'error': 'Invalid or expired code'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = CustomUser.objects.get(email=email)
            user.set_password(new_password)
            user.save()
            
            # Delete the reset code from Redis
            redis_client.delete(redis_key)
            
            return Response({
                'message': 'Password reset successful'
            }, status=status.HTTP_200_OK)
            
        except CustomUser.DoesNotExist:
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
            
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)