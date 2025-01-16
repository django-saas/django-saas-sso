from django.urls import path, include

urlpatterns = [
    path('m/', include('saas_sso.management_api.urls')),
    path('m/', include('saas_sso.management_views.urls')),
]
