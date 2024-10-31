# views.py
import logging

import requests
from django.conf import settings
from django.contrib.auth import login
from django.shortcuts import redirect
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from google.auth.transport import requests
from rest_framework import generics, status, viewsets
from rest_framework import permissions
from rest_framework.authtoken.models import Token
from rest_framework.parsers import FileUploadParser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from config import settings

from base.permissions import IsOwner
from .models import User
from .serializers import UserSerializer, LoginSerializer, SignUpSerializer, TokenSerializer


logger = logging.getLogger('authentication')


# Get User API
class UserAPI(viewsets.ModelViewSet):
    """
    A viewset for the User API that allows authenticated users to retrieve and update their own user object.
    """

    # Define the permissions required to access this viewset
    permission_classes = [
        permissions.IsAuthenticated, IsOwner
    ]

    # Set the serializer class used to serialize and deserialize user data
    serializer_class = UserSerializer

    # Define the allowed HTTP methods for this viewset
    http_method_names = ['get', 'put', 'patch']

    # Define the queryset used to retrieve user data
    queryset = User.objects.all()

    def get_object(self):
        """
        Retrieve the user object for the currently authenticated user.
        """
        return self.request.user

    def get_queryset(self):
        """
        Retrieve the queryset of user objects filtered to include only the currently authenticated user.
        """
        return User.objects.filter(id=self.request.user.id)


class Profile(viewsets.ViewSet):
    """
    A viewset for the user profile API that allows authenticated users to retrieve and update their own profile data.
    """

    # Define the permissions required to access this viewset
    permission_classes = [
        permissions.IsAuthenticated, IsOwner
    ]

    # Set the serializer class used to serialize and deserialize user data
    serializer_class = UserSerializer
    parser_class = [FileUploadParser]

    @swagger_auto_schema(responses={200: UserSerializer(many=False)})
    def list(self, request):
        """
        Retrieve the profile data for the currently authenticated user.
        """
        logger.info(f"User {request.user.id} is accessing their profile data.")
        queryset = User.objects.get(id=request.user.id)
        logger.info(
            f"Profile data for user {request.user.id} has been retrieved.")
        serializer = UserSerializer(queryset)
        return Response(serializer.data)

    @swagger_auto_schema(responses={200: UserSerializer(many=False)})
    def partial_update(self, request):
        """
        Update the profile data for the currently authenticated user.
        """
        logger.info(f"User {request.user.id} is updating their profile data.")
        user = User.objects.get(id=request.user.id)
        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            logger.info(
                f"Profile data for user {request.user.id} has been updated.",
                extra={
                    'data': serializer.data})
            user.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    def post(self, request, *args, **kwargs):
        """
        Log out the currently authenticated user by blacklisting their refresh token.
        """
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            try:
                token.blacklist()
            except AttributeError:
                # The token is already blacklisted
                pass

            logger.info(f"User {request.user.id} has been logged out.")
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except TokenError:
            logger.warning(f"User {request.user.id} is logging out failed.",
                           extra={'data': "Invalid token"})
            return Response(status=status.HTTP_400_BAD_REQUEST, data={
                "message": "Invalid token"})
        except Exception as e:
            logger.warning(f"User {request.user.id} is logging out failed.{type(e)}")
            return Response(status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        """
        Logs in the user with email and password.
        """
        email = request.data.get('email')
        password = request.data.get('password')
        if email and password:
            try:
                user = User.objects.filter(email=email).first()
                if user:
                    if user.check_password(password):
                        token = RefreshToken.for_user(user)
                        return Response({
                            'refresh': str(token),
                            'access': str(token.access_token),
                        })
                    else:
                        # Invalid password
                        return Response(
                            status=status.HTTP_401_UNAUTHORIZED, data={
                                "message": "Invalid email or password"})
                else:
                    # User not found with the given email
                    return Response(
                        status=status.HTTP_401_UNAUTHORIZED, data={
                            "message": "Invalid email or password"})
            except Exception as e:
                print(e)
                logger.warning(f"User  is logging in failed.",
                               extra={'data': e})
                return Response(status=status.HTTP_400_BAD_REQUEST)
        else:

            logger.warning(f"User  is logging in failed.", extra={
                'data': "email and password are required"})
            # Invalid request, missing email or password
            return Response(status=status.HTTP_400_BAD_REQUEST, data={
                "message": "email and password are required"})


class SignUpView(generics.CreateAPIView):
    serializer_class = SignUpSerializer

    @swagger_auto_schema(
        request_body=serializer_class,
        responses={
            status.HTTP_201_CREATED: openapi.Response(
                description="User created successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                        'access': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Bad request",
                schema=TokenSerializer,
            ),

        },
        swagger_auto_schema=None,

    )
    def create(self, request, *args, **kwargs):
        """
        Creates a new user.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        token = RefreshToken.for_user(user)
        return Response({
            'refresh': str(token),
            'access': str(token.access_token),
        }, status=status.HTTP_201_CREATED)


def google_login(request):
    host_url = request.build_absolute_uri('/')[:-1]
    next_ = request.GET.get('next', settings.REACT_APP_URL)
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
    profile = user_info.get('picture', None)  # Handle missing profile picture

    # Check if user exists, else create a new user
    try:
        user = User.objects.get(email=email)
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
        return redirect(settings.REACT_APP_URL + f'/login?token={token.key}')
