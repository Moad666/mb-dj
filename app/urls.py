from django.urls import path
from .views import *


urlpatterns = [
    # Register
    path('register', Register.as_view(), name='register'),
    path('login', Login.as_view(), name='login'),
]