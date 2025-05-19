from django.urls import path
from .views import *


urlpatterns = [
    # Login & Register
    path('register', Register.as_view(), name='register'),
    path('login', Login.as_view(), name='login'),

    # Password
    path('forgotpassword', forgotPassword, name='forgot_password'),
    path('resetpassword/<int:user_id>', resetpassword, name='reset_password'),
]