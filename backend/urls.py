from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_user, name='register'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('password-reset/request/', views.request_password_reset, name='request-password-reset'),
    path('password-reset/verify/', views.verify_reset_code, name='verify-reset-code'),
    path('password-reset/reset/', views.reset_password, name='reset-password'),

]