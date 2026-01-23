from drf_spectacular.extensions import OpenApiViewExtension
from drf_spectacular.utils import extend_schema
from saas_sso.serializers import UsernameSerializer


class FixedUserIdentityListEndpoint(OpenApiViewExtension):
    target_class = 'saas_sso.endpoints.identities.UserIdentityListEndpoint'

    def view_replacement(self):
        class UserIdentityListEndpoint(self.target_class):
            @extend_schema(tags=['SSO'], summary='List user identities')
            def get(self, *args, **kwargs):
                pass

        return UserIdentityListEndpoint


class FixedUserIdentityItemEndpoint(OpenApiViewExtension):
    target_class = 'saas_sso.endpoints.identities.UserIdentityItemEndpoint'

    def view_replacement(self):
        class UserIdentityItemEndpoint(self.target_class):
            @extend_schema(tags=['SSO'], summary='Disconnect user identity')
            def delete(self, *args, **kwargs):
                pass

        return UserIdentityItemEndpoint


class FixedSessionUserInfoEndpoint(OpenApiViewExtension):
    target_class = 'saas_sso.endpoints.session.SessionUserInfoEndpoint'

    def view_replacement(self):
        class SessionUserInfoEndpoint(self.target_class):
            @extend_schema(tags=['SSO'], summary='Get session user info')
            def get(self, *args, **kwargs):
                pass

        return SessionUserInfoEndpoint


class FixedSessionCreateUserEndpoint(OpenApiViewExtension):
    target_class = 'saas_sso.endpoints.session.SessionCreateUserEndpoint'

    def view_replacement(self):
        class SessionCreateUserEndpoint(self.target_class):
            @extend_schema(tags=['SSO'], summary='Create user from session', request=UsernameSerializer)
            def post(self, *args, **kwargs):
                pass

        return SessionCreateUserEndpoint
