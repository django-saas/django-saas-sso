from django.urls import path
from .endpoints import UserIdentityListEndpoint

urlpatterns = [
    path('user/identities', UserIdentityListEndpoint.as_view()),
]
