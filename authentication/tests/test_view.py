import pytest
import requests
from unittest.mock import patch
from django.urls import reverse
from django.conf import settings
from rest_framework.test import APIClient
from authentication.models import User
from rest_framework.authtoken.models import Token


@pytest.mark.django_db
class TestGoogleOAuth:
    def test_google_login_redirect(self, client):
        url = reverse('google_login')  # Adjust if the URL pattern name is different
        response = client.get(url)
        assert response.status_code == 302
        assert "accounts.google.com/o/oauth2/v2/auth" in response.url

    @patch('requests.post')
    @patch('requests.get')
    def test_google_callback_creates_user_and_logs_in(self, mock_get, mock_post, client):
        mock_token_response = {
            'access_token': 'test-access-token',
        }
        mock_user_info = {
            'email': 'testuser@example.com',
            'name': 'Test User',
            'picture': 'https://example.com/profile.jpg'
        }

        mock_post.return_value.json.return_value = mock_token_response
        mock_get.return_value.json.return_value = mock_user_info

        callback_url = reverse('google_callback')  # Adjust if the URL pattern name is different
        response = client.get(callback_url, {'code': 'test-code', 'state': settings.AUTH_SUCCESS_REDIRECT})

        user = User.objects.get(email=mock_user_info['email'])
        token = Token.objects.get(user=user)

        assert response.status_code == 302
        assert response.url == f"{settings.AUTH_SUCCESS_REDIRECT}/login?token={token.key}"
        assert user.is_authenticated
        assert user.full_name == mock_user_info['name']
        # assert user.profile == mock_user_info['picture']

    @patch('requests.post')
    def test_google_callback_token_error(self, mock_post, client):
        mock_post.return_value.json.return_value = {'error': 'invalid_grant'}

        callback_url = reverse('google_callback')
        response = client.get(callback_url, {'code': 'test-code'})

        assert response.status_code == 302
        assert response.url == reverse('google_login')


    @patch('requests.post')
    def test_google_callback_token_error_in_response(self, mock_post, client):
        # Mock an error in the token response
        mock_post.return_value.json.return_value = {'error': 'invalid_grant'}

        callback_url = reverse('google_callback')
        response = client.get(callback_url, {'code': 'test-code'})

        assert response.status_code == 302
        assert response.url == reverse('google_login')  # Should redirect back to Google login


    @patch('requests.post')
    @patch('requests.get')
    def test_google_callback_user_not_active(self, mock_get, mock_post, client):
        # Set up mock responses and create an inactive user
        mock_token_response = {
            'access_token': 'test-access-token',
        }
        mock_user_info = {
            'email': 'inactiveuser@example.com',
            'name': 'Inactive User',
            'picture': 'https://example.com/profile.jpg'
        }

        mock_post.return_value.json.return_value = mock_token_response
        mock_get.return_value.json.return_value = mock_user_info

        # Create the user but make it inactive
        user = User.objects.create(email='inactiveuser@example.com', is_active=False,full_name='Inactive User')

        # Trigger the callback view
        callback_url = reverse('google_callback')
        response = client.get(callback_url, {'code': 'test-code', 'state': settings.AUTH_SUCCESS_REDIRECT})

        user.refresh_from_db()

        # Ensure the inactive user is now active and that the response redirects with token
        token = Token.objects.get(user=user)
        assert response.status_code == 302
        assert response.url == f"{settings.AUTH_SUCCESS_REDIRECT}/login?token={token.key}"
        assert user.is_active

    @patch('requests.post')
    @patch('requests.get')
    def test_google_callback_no_access_token(self, mock_get, mock_post, client):
        # Mock a response without access token
        mock_post.return_value.json.return_value = {}

        callback_url = reverse('google_callback')
        response = client.get(callback_url, {'code': 'test-code'})

        assert response.status_code == 302
        assert response.url == reverse('google_login')  # Should redirect to Google login


@pytest.mark.django_db
class TestProfileView:
    @pytest.fixture
    def authenticated_client(self):
        _user = User.objects.create_user(email='profileuser@example.com', password='Password@123',full_name='Profile User')
        token = Token.objects.create(user=_user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
        return client, _user

    def test_profile_view_get(self, authenticated_client):
        client, user = authenticated_client
        response = client.get(reverse('profile'))  # Adjust if the URL pattern name is different

        assert response.status_code == 200
        assert response.data['email'] == user.email
        assert response.data['full_name'] == user.full_name
        # assert response.data['profile'] == user.profile

    def test_profile_view_put(self, authenticated_client):
        client, user = authenticated_client
        new_data = {
            'full_name': 'Updated User',
            'profile': 'https://example.com/newprofile.jpg'
        }
        response = client.put(reverse('profile'), new_data, format='json')

        user.refresh_from_db()

        assert response.status_code == 200
        assert response.data['full_name'] == new_data['full_name']
        # assert response.data['profile'] == new_data['profile']
        assert user.full_name == new_data['full_name']
        assert user.profile == new_data['profile']
