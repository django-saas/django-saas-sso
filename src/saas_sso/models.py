import uuid
from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.utils import timezone


class UserIdentity(models.Model):
    id = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='identities',
    )
    strategy = models.CharField(max_length=24, db_index=True)
    subject = models.CharField(max_length=100, editable=False)
    profile = models.JSONField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("identity")
        verbose_name_plural = _("identities")
        unique_together = [
            ['strategy', 'subject'],
        ]
        ordering = ['strategy', 'subject']
        db_table = "saas_user_identity"

    def __str__(self):
        return self.subject
