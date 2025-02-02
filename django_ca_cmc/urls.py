"""URL configuration for the django-ca-cmc app."""

from django.urls import URLPattern, URLResolver, path

from django_ca_cmc import views

app_name = "django_ca_cmc"

urlpatterns: list[URLResolver | URLPattern] = [
    path("<serial:serial>/", views.CMCView.as_view(), name="cmc"),
]
