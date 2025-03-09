from django.urls import path, include
from django.contrib import admin
from django.contrib.staticfiles.urls import urlpatterns as static_urlpatterns
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from .views import index, profile

urlpatterns = [
    path('', index, name='index'),
    path('accounts/profile/', profile),
    path('admin/', admin.site.urls),
    path('api/user/', include('saas_sso.api_urls')),
    path('', include('saas_sso.auth.urls')),
    path('schema/openapi', SpectacularAPIView.as_view(), name='schema'),
    path('schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('schema/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
] + static_urlpatterns
