from django.urls import path
from rest_framework_simplejwt import views as jwt_views

from . import views

urlpatterns = [
    path('', views.google_login, name='google_login'),
    path('google/callback/', views.google_callback, name='google_callback'),
    path("profile/", views.Profile.as_view(
        {"get": "list", "patch": "partial_update"}
    ), name="profile"),
]
