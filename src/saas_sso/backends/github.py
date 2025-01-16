from ._oauth2 import OAuth2Provider
from .types import OAuth2Token


class GitHubProvider(OAuth2Provider):
    strategy = 'github'
    authorization_endpoint = 'https://github.com/login/oauth/authorize'
    token_endpoint = 'https://github.com/login/oauth/access_token'
    userinfo_endpoint = 'https://api.github.com/user'
    scope = 'read:user user:email'

    def fetch_userinfo(self, token: OAuth2Token):
        resp = self.get(self.userinfo_endpoint, token=token)
        resp.raise_for_status()
        user = resp.json()
        email_info = self.fetch_primary_email(token)
        name = user.get("name")
        if name:
            parts = name.split()
            given_name = parts[0]
            if len(parts) == 2:
                family_name = parts[1]
            else:
                family_name = None
        else:
            given_name = user["login"]
            family_name = None
        info = {
            "sub": str(user["id"]),
            "preferred_username": user["login"],
            "picture": user["avatar_url"],
            "website": user.get("blog"),
            "given_name": given_name,
            "family_name": family_name,
            "email": email_info.get("email"),
            "email_verified": email_info.get("verified"),
        }
        return info

    def fetch_primary_email(self, token: OAuth2Token):
        resp = self.get("https://api.github.com/user/emails", token=token)
        resp.raise_for_status()
        emails = resp.json()
        primaries = [d for d in emails if d["primary"]]
        if primaries:
            return primaries[0]
        if emails:
            return emails[0]
        return {}
