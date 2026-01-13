from django.urls import path
from .endpoints.identities import UserIdentityListEndpoint, UserIdentityItemEndpoint

urlpatterns = [
    path('identities/', UserIdentityListEndpoint.as_view()),
    path('identities/<pk>/', UserIdentityItemEndpoint.as_view()),
]
