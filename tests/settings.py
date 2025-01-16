SECRET_KEY = 'django-insecure'
ALLOWED_HOSTS = ['*']
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
            ]
        }
    }
]
MIDDLEWARE = [
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'saas_base.drf.middleware.HeaderTenantIdMiddleware',
    'saas_base.drf.middleware.TenantMiddleware',
]
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {
            "min_length": 8,
        },
    },
]
INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sessions',
    'saas_base',
    'saas_sso',
]
REST_FRAMEWORK = {
    'TEST_REQUEST_DEFAULT_FORMAT': 'json',
    'DEFAULT_AUTHENTICATION_CLASSES': ['saas_base.drf.authentication.SessionAuthentication'],
    'DEFAULT_PERMISSION_CLASSES': ['saas_base.drf.permissions.HasResourcePermission'],
    'DEFAULT_RENDERER_CLASSES': ['rest_framework.renderers.JSONRenderer'],
    'DEFAULT_PARSER_CLASSES': ['rest_framework.parsers.JSONParser'],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 10,
}
SAAS_SSO = {
    'PROVIDERS': [
        {
            'backend': 'saas_sso.backends.GoogleProvider',
            'options': {
                'client_id': 'google_client_id',
                'client_secret': 'google_client_secret',
            },
        },
        {
            'backend': 'saas_sso.backends.GitHubProvider',
            'options': {
                'client_id': 'github_client_id',
                'client_secret': 'github_client_secret',
            },
        },
    ]
}
USE_TZ = True
TIME_ZONE = 'UTC'
ROOT_URLCONF = 'tests.urls'
