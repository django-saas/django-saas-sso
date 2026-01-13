# Project Context
`django-saas-sso` is a Django app that provides Single Sign-On (SSO) functionality for SaaS applications. It is designed to work with `django-saas-base` and supports multiple OAuth2 providers (e.g., Google, GitHub, Apple).

## Codebase Structure
- **`src/saas_sso/`**: The core library source code.
  - **`backends/`**: Implementation of SSO providers.
    - `_oauth2.py`: Abstract base class `OAuth2Provider` for OAuth2 flows.
    - `apple.py`, `github.py`, `google.py`: Concrete provider implementations.
  - **`endpoints/`**: API views and endpoints handling auth flows.
  - **`auth/`**: Custom Django authentication backends.
  - **`models.py`**: Defines `UserIdentity` model linking Django users to external identities.
  - **`serializers.py`**: DRF serializers for the models.
- **`demo/`**: A sample Django project demonstrating usage.
- **`tests/`**: Pytest suite ensuring reliability.
- **`pyproject.toml`**: Project metadata, dependencies, and tool configurations.

## Architecture & Patterns

### 1. SSO Providers (`src/saas_sso/backends/`)
- All OAuth2 providers inherit from `OAuth2Provider` (defined in `_oauth2.py`).
- **Key Methods**:
  - `create_authorization_url(request, redirect_uri)`: Generates the provider's login URL.
  - `fetch_token(request)`: Exchanges the authorization code for an access token.
  - `fetch_userinfo(token)`: Abstract method to retrieve user profile data.
- **State Management**: Uses Django's `cache` to store the `state` parameter and prevent CSRF attacks.

### 2. Identity Model (`src/saas_sso/models.py`)
- **`UserIdentity`**: The central model.
  - `user`: ForeignKey to the Django User model.
  - `strategy`: The provider name (e.g., 'google').
  - `subject`: The unique user ID from the provider.
  - `profile`: JSONField storing raw profile data.
  - **Constraints**: Enforces unique `(strategy, subject)` and `(user, strategy)` pairs.

### 3. Authentication Flow
- The flow typically involves:
  1. Frontend requests an authorization URL.
  2. User redirects to provider -> logs in -> redirects back to callback.
  3. Backend exchanges code for token using `fetch_token`.
  4. Backend fetches user info.
  5. `UserIdentity` is created/updated, and the Django user is logged in.

## Development Guidelines

### Standards
- **Linter/Formatter**: `ruff` is used. Configuration is in `pyproject.toml`.
  - Line length: 120.
  - Quote style: Single quotes.
- **Testing**: `pytest` is the test runner.
  - Run tests with: `pytest`
  - Ensure high coverage for auth flows.

### Best Practices
- **Security**:
  - Always validate state/nonce in OAuth flows.
  - Never log sensitive tokens (access tokens, client secrets).
  - Use `uuid` for internal IDs where possible.
- **Modularity**: New providers should be added as new modules in `src/saas_sso/backends/`.

## Key Files to Reference
- `pyproject.toml`: Dependencies and tool settings.
- `src/saas_sso/models.py`: Database schema.
- `src/saas_sso/backends/_oauth2.py`: Core logic for OAuth2.
- `tests/`: Existing tests provide good usage examples.
