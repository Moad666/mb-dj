from django.shortcuts import render
from .models import User
from .serializers import UserSerializer

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
import jwt,datetime
from rest_framework import generics,status, viewsets
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.decorators import api_view
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password
from rest_framework.decorators import action


# Register 
class Register(APIView):
    def post(self,request):
        serializer = UserSerializer(data = request.data)
        serializer.is_valid(raise_exception = True)
        serializer.save()
        return Response(serializer.data)

# User Authentication
class Login(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found')
        
        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password')
        
        # exp : sets the expiration time claim for the JWT
        # iat : specifies the time at which the token was issued
        payload= {
            'id' : user.id,
            'email': user.email,
            'name': user.name,
            'date_joined': user.date_joined.strftime('%Y-%m-%d'),
            'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat' : datetime.datetime.utcnow()
            #'is_active' : user.is_active,
        }
        token = jwt.encode(payload, 'secret', algorithm='HS256')
        
        response = Response()
        response.set_cookie(key='token', value=token, httponly=True)
        response.data = {'token': token, 'email': user.email, 'name': user.name, 'date_joined': payload['date_joined'], 'id': payload['id']}
        
        return response