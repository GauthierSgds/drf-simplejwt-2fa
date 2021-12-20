from django.contrib.auth import authenticate, get_user_model
from rest_framework import exceptions, serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.models import update_last_login
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, serializers
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken, SlidingToken, UntypedToken
from rest_framework_simplejwt.serializers import PasswordField
from rest_framework_jwt.settings import api_settings as jwt_settings

from .token_manager import CodeTokenManager
from .utils import check_user_validity

jwt_encode_handler = jwt_settings.JWT_ENCODE_HANDLER
jwt_payload_handler = jwt_settings.JWT_PAYLOAD_HANDLER

from rest_framework import serializers


class JwtSerializer(serializers.Serializer):
    @property
    def object(self):
        return self.validated_data


class Jwt2faSerializer(JwtSerializer):
    token_manager_class = CodeTokenManager

    def __init__(self, *args, **kwargs):
        super(Jwt2faSerializer, self).__init__(*args, **kwargs)
        self.token_manager = self.token_manager_class()

    def validate(self, attrs):
        validated_attrs = super(Jwt2faSerializer, self).validate(attrs)
        user = self._authenticate(validated_attrs)
        return {
            'token': self._create_token(user),
        }


class CodeTokenSerializer(Jwt2faSerializer):
    username = serializers.CharField(required=True)
    password = PasswordField(write_only=True, required=True)

    def _authenticate(self, attrs):
        credentials = {
            'username': attrs.get('username'),
            'password': attrs.get('password'),
        }
        user = authenticate(**credentials)
        if not user:
            raise exceptions.AuthenticationFailed()
        check_user_validity(user)
        return user

    def _create_token(self, user):
        return self.token_manager.create_code_token(user)


class AuthTokenSerializer(Jwt2faSerializer):
    code_token = serializers.CharField(required=True)
    code = PasswordField(write_only=True, required=True)

    def _authenticate(self, attrs):
        code_token = attrs.get('code_token')
        code = attrs.get('code')
        username = self._check_code_token_and_code(code_token, code)
        user = self._get_user(username)
        return user

    def _check_code_token_and_code(self, code_token, code):
        return self.token_manager.check_code_token_and_code(code_token, code)

    def _get_user(self, username):
        user_model = get_user_model()
        try:
            user = user_model.objects.get_by_natural_key(username)
        except user_model.DoesNotExist:
            raise exceptions.AuthenticationFailed()
        check_user_validity(user)
        return user

    def _create_token(self, user):
        payload = jwt_payload_handler(user)
        return jwt_encode_handler(payload)


class TokenObtainSerializer(serializers.Serializer):
    token_manager_class = CodeTokenManager

    default_error_messages = {
        "no_active_account": _("No active account found with the given credentials")
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["code_token"] = serializers.CharField()
        self.fields["code"] = serializers.CharField()

    def _get_user(self, username):
        user_model = get_user_model()
        try:
            user = user_model.objects.get_by_natural_key(username)
        except user_model.DoesNotExist:
            raise exceptions.AuthenticationFailed()
        check_user_validity(user)
        return user

    def _authenticate(self, attrs):
        code_token = attrs.get("code_token")
        code = attrs.get("code")
        username = self.token_manager_class().check_code_token_and_code(code_token, code)
        user = self._get_user(username)
        return user

    def validate(self, attrs):
        authenticate_kwargs = {
            "code_token": attrs["code_token"],
            "code": attrs["code"],
        }
        try:
            authenticate_kwargs["request"] = self.context["request"]
        except KeyError:
            pass

        self.user = self._authenticate(authenticate_kwargs)

        if not api_settings.USER_AUTHENTICATION_RULE(self.user):
            raise exceptions.AuthenticationFailed(
                self.error_messages["no_active_account"],
                "no_active_account",
            )

        return {}

    @classmethod
    def get_token(cls, user):
        raise NotImplementedError(
            "Must implement `get_token` method for `TokenObtainSerializer` subclasses"
        )


class TokenObtainPairSerializer(TokenObtainSerializer):
    @classmethod
    def get_token(cls, user):
        return RefreshToken.for_user(user)

    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = self.get_token(self.user)

        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        return data


class TokenObtainSlidingSerializer(TokenObtainSerializer):
    @classmethod
    def get_token(cls, user):
        return SlidingToken.for_user(user)

    def validate(self, attrs):
        data = super().validate(attrs)

        token = self.get_token(self.user)

        data["token"] = str(token)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        return data