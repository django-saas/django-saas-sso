from django.urls import path, include

urlpatterns = [
    path('m/', include('saas_sso.api_urls')),
    path('m/', include('saas_sso.auth_urls')),
]
