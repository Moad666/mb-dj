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
from django.core.mail import send_mail



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




# Forgot password
@api_view(['POST'])
def forgotPassword(request):
    try:
        email = request.data.get('email')
        print(f"Email received: {email}")
        verify = User.objects.filter(email=email).first()
        if verify:
            link = f"http://localhost:3000/resetpassword/{verify.id}"
            print(f"Reset link: {link}")
            send_mail(
                subject='Reset your password',
                message=f'We have received a request to reset the password associated with your account on our E-learning platform. To proceed with resetting your password, please click the link below:{link}',
                from_email='Moroccan Blog',
                recipient_list=[email],
                fail_silently=False,
            )
            return Response({'message': 'Forgot password success'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Reset password failed'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        print(f"Error: {e}")
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# reset password
@api_view(['POST'])
def resetpassword(request, user_id):
    try:
        password = request.data.get('password')
        verify = User.objects.filter(id=user_id).first()
        if verify:
            hashed_password = make_password(password)
            User.objects.filter(id=user_id).update(password=hashed_password)
            return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': "Password didn't change"}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        print(f"Error: {e}")
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)