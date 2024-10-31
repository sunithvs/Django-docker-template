import logging

import requests
from django.conf import settings
from django.contrib.auth import login
from django.shortcuts import redirect
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.models import User
from config import settings

logger = logging.getLogger('authentication')


def google_login(request):
    host_url = request.build_absolute_uri('/')[:-1]
    next_ = request.GET.get('next', settings.AUTH_SUCCESS_REDIRECT)
    google_oauth_url = (
            'https://accounts.google.com/o/oauth2/v2/auth'
            '?response_type=code'
            f'&client_id={settings.GOOGLE_CLIENT_ID}'
            f'&redirect_uri={host_url}/{settings.GOOGLE_REDIRECT_URI}'
            '&scope=email%20profile'
            '&access_type=offline'
            '&prompt=consent' + f'&state={next_}'
    )
    return redirect(google_oauth_url)


def google_callback(request):
    code = request.GET.get('code')
    if not code:
        logger.error('Google OAuth code not found')
        return redirect('google_login')  # Or handle with an error message
    state = request.GET.get('state', '')
    host_url = request.build_absolute_uri('/')[:-1]
    token_url = 'https://oauth2.googleapis.com/token'
    token_data = {
        'code': code,
        'client_id': settings.GOOGLE_CLIENT_ID,
        'client_secret': settings.GOOGLE_CLIENT_SECRET,
        'redirect_uri': f'{host_url}/{settings.GOOGLE_REDIRECT_URI}',
        'grant_type': 'authorization_code',
    }

    token_response = requests.post(token_url, data=token_data)
    token_json = token_response.json()

    access_token = token_json.get('access_token')

    if not access_token:
        logger.error(f"Google OAuth token error: {token_json}")
        return redirect('google_login')
    if 'error' in token_json:
        logger.error(f"Google OAuth token error: {token_json['error']}")
        return redirect('google_login')  # Optionally, show a more descriptive error message

    # Fetch user information
    user_info_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    user_info_params = {'access_token': access_token}
    user_info_response = requests.get(user_info_url, params=user_info_params)
    user_info = user_info_response.json()

    # Create or log in the user
    email = user_info.get('email')
    name = user_info.get('name', email.split("@")[0])
    profile = user_info.get('picture')

    # Check if user exists, else create a new user
    try:
        user = User.objects.get(email=email)
        user.profile = profile
    except User.DoesNotExist:
        user = User.objects.create(email=email, full_name=name, profile=profile)
    if not user.is_active:
        user.is_active = True
        user.full_name = name
    user.save()
    login(request, user)
    token = Token.objects.get_or_create(user=user)[0]
    try:
        return redirect(state + f'/login?token={token.key}')
    # if state is none
    except:
        return redirect(settings.AUTH_SUCCESS_REDIRECT + f'/login?token={token.key}')


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            'email': user.email,
            'full_name': user.full_name,
            'profile': user.profile
        })

    def put(self, request):
        user = request.user
        data = request.data
        user.full_name = data.get('full_name', user.full_name)
        user.profile = data.get('profile', user.profile)
        user.save()
        return Response({
            'email': user.email,
            'full_name': user.full_name,
            'profile': user.profile
        })
