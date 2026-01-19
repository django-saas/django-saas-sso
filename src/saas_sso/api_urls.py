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
    path('sso/userinfo/', SessionUserInfoEndpoint.as_view()),
    path('sso/create-user/', SessionCreateUserEndpoint.as_view()),
    path('user/identities/', UserIdentityListEndpoint.as_view()),
    path('user/identities/<pk>/', UserIdentityItemEndpoint.as_view()),
]
