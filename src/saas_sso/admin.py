from django.contrib import admin
from .models import UserIdentity


@admin.register(UserIdentity)
class UserIdentityAdmin(admin.ModelAdmin):
    list_display = ["pk", "subject", "strategy", "user", "created_at"]
    list_filter = ("strategy",)
