import os
DEBUG = True
TESTING = True
SECRET_KEY = 'django-insecure'
ALLOWED_HOSTS = ['*']
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "db.sqlite3",
    }
}
AUTHENTICATION_BACKENDS = [
    "saas_base.auth_backends.PasswordLoginBackend",
    "saas_sso.auth_backends.UserIdentityBackend",
]
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'saas_base.drf.middleware.HeaderTenantIdMiddleware',
    'saas_base.drf.middleware.TenantMiddleware',
]
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            "demo/templates",
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ]
        }
    }
]
SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
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
    'django.contrib.staticfiles',
    'django.contrib.messages',
    'django.contrib.admin',
    'rest_framework',
    'drf_spectacular',
    'saas_base',
    'saas_base.drf',
    "saas_sso",
]
REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': ['rest_framework.parsers.JSONParser'],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 10,
    'DEFAULT_SCHEMA_CLASS': 'saas_base.drf.spectacular.AutoSchema',
}
SPECTACULAR_SETTINGS = {
    'TITLE': 'Django SaaS',
    'DESCRIPTION': 'Django SaaS help you building SaaS project',
    'VERSION': '1.0.0',
    'SCHEMA_PATH_PREFIX': '/api',
    'SERVE_INCLUDE_SCHEMA': False,
}

SAAS_SSO = {
    'TRUST_EMAIL_VERIFIED': True,
    'PROVIDERS': [
        {
            'backend': 'saas_sso.backends.GoogleProvider',
            'options': {
                'client_id': os.getenv('GOOGLE_CLIENT_ID'),
                'client_secret': os.getenv('GOOGLE_CLIENT_SECRET'),
            },
        },
        {
            'backend': 'saas_sso.backends.GitHubProvider',
            'options': {
                'client_id': os.getenv('GITHUB_CLIENT_ID'),
                'client_secret': os.getenv('GITHUB_CLIENT_SECRET'),
            },
        },
    ]
}

STATIC_URL = 'static/'
USE_TZ = True
TIME_ZONE = 'UTC'
ROOT_URLCONF = 'demo.urls'
