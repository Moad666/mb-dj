from rest_framework import serializers
from .models import User

# User Serializer

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'password']

        #ensure that the password is not included when serializing the object (e.g., when sending the object's data in an API response)
        extra_kwargs = {
            'password' : {'write_only':True}
        }

    def create(self, validated_data):
        #extract password data
        password = validated_data.pop('password', None)
        #we access to meta model user then validated_data contain the data send it in request then the ** extract the data from validated_data
        instance = self.Meta.model(**validated_data)
        if password is not None:
            # hash password
            instance.set_password(password)
        instance.save()
        return instance