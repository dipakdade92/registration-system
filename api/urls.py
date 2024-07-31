from django.contrib import admin
from django.urls import path, include
from api.views import login, signup


urlpatterns = [
    path("auth/signup/", signup),
    path("auth/login/", login),
]
