from rest_framework import serializers
from .models import User
import re

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role']  # তোমার মডেলের ফিল্ড অনুযায়ী


class SignUpSerializer(serializers.ModelSerializer):
       password = serializers.CharField(write_only=True)
       confirm_password = serializers.CharField(write_only=True)

       class Meta:
           model = User
           fields = ['username', 'email', 'password', 'confirm_password']

       def validate(self, data):
           if data['password'] != data['confirm_password']:
               raise serializers.ValidationError("Passwords do not match.")
           if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', data['password']):
               raise serializers.ValidationError("Password must be at least 8 characters long and contain letters and numbers.")
           return data

       def create(self, validated_data):
           validated_data.pop('confirm_password')
           user = User.objects.create_user(
               username=validated_data['username'],
               email=validated_data['email'],
               password=validated_data['password'],
               role='user'
           )
           return user

class LoginSerializer(serializers.Serializer):
       email = serializers.EmailField()
       password = serializers.CharField()

class EmailVerificationSerializer(serializers.Serializer):
       email = serializers.EmailField()
       code = serializers.CharField(max_length=6)