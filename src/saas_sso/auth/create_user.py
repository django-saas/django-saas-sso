import uuid
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.utils import IntegrityError
from saas_base.identity.models import UserEmail
from saas_sso.models import UserIdentity
from saas_sso.types import UserInfo


def create_user_with_userinfo(username: str, strategy: str, userinfo: UserInfo):
    UserModel = get_user_model()

    try:
        with transaction.atomic():
            user = UserModel.objects.create_user(
                username,
                userinfo['email'],
                first_name=userinfo.get('given_name') or '',
                last_name=userinfo.get('family_name') or '',
            )
    except IntegrityError:
        user = UserModel.objects.create_user(
            uuid.uuid4().hex,
            userinfo['email'],
            first_name=userinfo.get('given_name') or '',
            last_name=userinfo.get('family_name') or '',
        )

    UserIdentity.objects.create(
        strategy=strategy,
        user=user,
        subject=userinfo['sub'],
        profile=userinfo,
    )

    # auto add user email
    if userinfo['email_verified']:
        UserEmail.objects.create(
            user_id=user.pk,
            email=userinfo['email'],
            verified=True,
            primary=True,
        )
    return user
