from django.urls import path
from .views import LoginView, AuthorizedView

app_name = 'saas_sso'

urlpatterns = [
    path("login/<strategy>/", LoginView.as_view(), name="login"),
    path("auth/<strategy>/", AuthorizedView.as_view(), name="auth"),
]
