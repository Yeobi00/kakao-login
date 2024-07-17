import os
import requests
import jwt

from rest_framework import viewsets, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.http import Http404

from .models import User
from .serializers import UserSerializer, KakaoLoginRequestSerializer, KakaoRegisterRequestSerializer

class KakaoAccessTokenException(Exception):
    pass

class KakaoDataException(Exception):
    pass

class KakaoOIDCException(Exception):
    pass

def exchange_kakao_access_token(access_code):
    response = requests.post(
        'https://kauth.kakao.com/oauth/token',
        headers={
            'Content-type': 'application/x-www-form-urlencoded;charset=utf-8',
        },
        data={
            'grant-type': 'authorization_code',
            'client_id': os.environ.get('KAKAO_REST_API_KEY'),
            'redirect_url': os.environ.get('KAKAO_REDIRECT_URI'),
            'code': access_code,
        },
    )
    if response.status_code >= 300:
        raise KakaoAccessTokenException()    
    return response.json()


def extract_kakao_nickname(kakao_data):
    id_token = kakao_data.get('id_token', None)
    if id_token is None:
        raise KakaoDataException()
    jwks_client = jwt.PyJWKClient(os.environ.get('KAKAO_OIDC_URI'))
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    signing_algol = jwt.get_unverified_header(id_token)['alg']
    try:
        payload = jwt.decode(
            id_token,
            key=signing_key.key,
            algorithms=[signing_algol],
            audience=os.environ.get('KAKAO_REST_API_KEY')
        )
    except jwt.InvalidTokenError:
        raise KakaoDataException()
    return payload['nickname']


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        queryset = self.get_queryset()
        if not queryset.exists():
            raise Http404("No Users in the list.")
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
        except:
            raise Http404("Not Existing User.")
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


class KakaoLoginViewSet(viewsets.ModelViewSet):
    permission_classes = [AllowAny]
    def create(self, request):
        serializer = KakaoLoginRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data 

        try:
            kakao_data = exchange_kakao_access_token(data['access_code'])
            nickname = extract_kakao_nickname(kakao_data)
        except KakaoAccessTokenException:
            return Response({'detail': 'Fail to access token exchange.'}, status=401)
        except KakaoDataException:
            return Response({'detail': 'Cannot verify OIDC token information.'}, status=401)
        except KakaoOIDCException:
            return Response({'detail': 'Fail to OIDC authentication.'}, status=401)
        
        try:
            user = User.objects.get(nickname=nickname)
        except User.DoesNotExist:
            return Response({'detail': 'Not existing User.'})
        
        refresh = RefreshToken.for_user(user)
        return Response({
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh)
        })


class KakaoRegisterViewSet(viewsets.ModelViewSet):
    permission_classes = [AllowAny]
    def create(self, request):
        serializer = KakaoRegisterRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data 

        try:
            kakao_data = exchange_kakao_access_token(data['access_code'])
            nickname = extract_kakao_nickname(kakao_data)
        except KakaoAccessTokenException:
            return Response({'detail': 'Fail to access token exchange.'}, status=401)
        except KakaoDataException:
            return Response({'detail': 'Cannot verify OIDC token information.'}, status=401)
        except KakaoOIDCException:
            return Response({'detail': 'Fail to OIDC authentication.'}, status=401)
        
        user = User.objects.create_user(nickname=nickname, mbti=data['mbti'], description=data['description'])
        refresh = RefreshToken.for_user(user)
        return Response({
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh)
        })


class VerifyViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    def get(self, request, *args, **kwargs):
        return Response({'detail': 'Token is verified.'}, status=200)
