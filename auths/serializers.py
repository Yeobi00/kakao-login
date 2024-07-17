from .models import User
from rest_framework import serializers, status
from rest_framework import permissions
from rest_framework.exceptions import APIException

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'nickname', 'mbti', 'description']

    # 닉네임 중복 검사
    def validate_nickname(self, value):
        if User.objects.filter(nickname=value).exists():
            raise DuplicateNicknameErrorException()
        return value

    # 프로필 수정
    def update(self, instance, validated_data):
        if instance != self.context['request'].user:
            raise serializers.ValidationError("Do not have authorization to update this profile.")
        instance.mbti = validated_data.get('mbti', instance.mbti)
        instance.description = validated_data.get('description', instance.description)
        instance.save()
        return instance

# JWT 발급
class KakaoLoginRequestSerializer(serializers.Serializer):
    access_code = serializers.CharField()

# 사용자 등록 및 JWT 발급
class KakaoRegisterRequestSerializer(serializers.Serializer):
    access_code = serializers.CharField()
    description = serializers.CharField()

# 닉네임 중복 에러
class DuplicateNicknameErrorException(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = 'Already Existing Nickname.'

# 수정 권한 확인
class IsOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj == request.user