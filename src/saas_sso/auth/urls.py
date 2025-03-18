from django.urls import path
from ..endpoints.auth import LoginView, AuthorizedView
from ..endpoints.connect import ConnectRedirectView, ConnectAuthorizedView

app_name = 'saas_sso'

urlpatterns = [
    path('login/<strategy>/', LoginView.as_view(), name='login'),
    path('auth/<strategy>/', AuthorizedView.as_view(), name='auth'),
    path('connect/link/<strategy>/', ConnectRedirectView.as_view()),
    path('connect/auth/<strategy>/', ConnectAuthorizedView.as_view(), name='connect'),
]
