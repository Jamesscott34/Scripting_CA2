"""URL routes for the CA2 banking app."""

from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("profile/", views.profile, name="profile"),
    path("search/", views.search, name="search"),
    path("register/", views.register, name="register"),
]
