# api/authentication.py

import jwt
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

class MockUser:
    def __init__(self):
        self.is_authenticated = True

class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        token = request.COOKIES.get('token')

        if not token:
   
            return None

        try:
            # Coba dekode token. Jika berhasil, berarti token valid.
            jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired!')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token!')
        return (MockUser(), None)