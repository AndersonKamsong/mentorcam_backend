from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from .views import ContactView, NewsletterView

# Create a router and register the UserViewSet
router = DefaultRouter()
router.register(r'users', views.UserViewSet, basename='user')

urlpatterns = [
    # Authentication URLs
    path('register/', views.register_user, name='register'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('current-user/', views.get_current_user, name='current-user'),

    
    # Password reset URLs
    path('password/reset/request/', views.request_password_reset, name='request-password-reset'),
    path('password/reset/verify/', views.verify_reset_code, name='verify-reset-code'),
    path('password/reset/confirm/', views.reset_password, name='reset-password'),
    
    # Contact and Newsletter URLs
    path('contact/', ContactView.as_view(), name='contact'),
    path('newsletter/', NewsletterView.as_view(), name='newsletter'),
    
    # Include the router URLs
    path('', include(router.urls)),
]