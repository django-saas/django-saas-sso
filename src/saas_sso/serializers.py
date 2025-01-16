from rest_framework import serializers
from .models import UserIdentity


class UserIdentitySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserIdentity
        exclude = ["user"]
