# Django SaaS (SSO)

The sso module for building a SaaS product with Django.

## Install

```
pip install django-saas-sso
```

Then add it into your Django project `settings.py`:

```python
INSTALLED_APPS = [
    # ...
    "saas_base",  # django-saas-base is required
    "saas_sso",
]
```
