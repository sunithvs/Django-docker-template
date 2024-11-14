from django.urls import path

from authentication import views

urlpatterns = [
    path('', views.google_login, name='google_login'),
    path('google/callback/', views.google_callback, name='google_callback'),
    path("profile/", views.ProfileView.as_view(), name="profile"),
]
