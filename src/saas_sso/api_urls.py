from django.urls import path
from .endpoints.identities import (
    UserIdentityListEndpoint,
    UserIdentityItemEndpoint,
)
from .endpoints.session import (
    SessionUserInfoEndpoint,
    SessionCreateUserEndpoint,
)

urlpatterns = [
    path('session/userinfo/', SessionUserInfoEndpoint.as_view()),
    path('session/create-user/', SessionCreateUserEndpoint.as_view()),
    path('identities/', UserIdentityListEndpoint.as_view()),
    path('identities/<pk>/', UserIdentityItemEndpoint.as_view()),
]
