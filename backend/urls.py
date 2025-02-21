from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from .views import BookingViewSet, ContactView, EventViewSet, JobViewSet, NewsletterView, PdfDocumentView, ProfessionalProfileView, PublicProfessionalProfileSearchView, ProfessionalCompleteProfileView, FileUploadView

# Create a router and register the UserViewSet
router = DefaultRouter()
router.register(r'users', views.UserViewSet, basename='user')
router.register(r'ratings', views.RatingViewSet, basename='rating')
router.register(r'bookings', BookingViewSet, basename='booking')
router.register(r'events', EventViewSet)
router.register(r'jobs', JobViewSet, basename='job')





urlpatterns = [
    # Authentication URLs
    path('register/', views.register_user, name='register'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('current-user/', views.get_current_user, name='current-user'),
    path('update-user/', views.UpdateUserView.as_view(), name='update-user'),


    
    # Password reset URLs
    path('password/reset/request/', views.request_password_reset, name='request-password-reset'),
    path('password/reset/verify/', views.verify_reset_code, name='verify-reset-code'),
    path('password/reset/confirm/', views.reset_password, name='reset-password'),
    
    # Contact and Newsletter URLs
    path('contact/', ContactView.as_view(), name='contact'),
    path('newsletter/', NewsletterView.as_view(), name='newsletter'),


    path('mentors/search/', PublicProfessionalProfileSearchView.as_view(), name='public-mentor-search'),

    path('professional-profile/', ProfessionalCompleteProfileView.as_view(), name='professional-profile'),
    path('professional-profile/<int:profile_id>/upload/', FileUploadView.as_view(), name='professional-profile-upload'),
    path('professionals/', views.list_professionals, name='list-professionals'),    
    path('professional-profile/<int:profile_id>/', ProfessionalProfileView.as_view()),
    path('professional-profile/<int:profile_id>/document/<str:document_type>/', PdfDocumentView.as_view()),





    # Include the router URLs
    path('', include(router.urls)),
]
