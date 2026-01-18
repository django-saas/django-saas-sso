from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import UserIdentity


class UserIdentitySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserIdentity
        exclude = ['user']


class UsernameSerializer(serializers.Serializer):
    username = serializers.CharField(validators=[get_user_model().username_validator])

    def validate_username(self, value: str):
        if get_user_model().objects.filter(username=value).exists():
            raise serializers.ValidationError('Username already exists.')
        return value
