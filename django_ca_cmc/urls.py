from typing import Union

from django.urls import URLPattern, URLResolver, path

from django_ca_cmc import views

app_name = "django_ca_cmc"

urlpatterns: list[URLResolver | URLPattern] = [
    path("cmc", views.CMCView.as_view(), name="cmc"),
]
