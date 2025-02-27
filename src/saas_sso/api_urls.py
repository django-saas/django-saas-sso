from django.urls import path
from .endpoints.identities import UserIdentityListEndpoint

urlpatterns = [
    path('identities/', UserIdentityListEndpoint.as_view()),
]
