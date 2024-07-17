from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

class UserManager(BaseUserManager):
    def create_user(self, nickname, mbti, description, password=None):
        if not nickname:
            raise ValueError('User must have a nickname')
        
        user = self.model(
            nickname = nickname,
            mbti = mbti,
            description = description,
        )
        user.set_password(password)
        user.save(using=self.db)
        return user
    
    def create_superuser(self, nickname, mbti, description, password=None):
        if not nickname:
            raise ValueError('User must have a nickname')
        
        user = self.create_user(
            nickname = nickname,
            mbti = mbti,
            description = description,
            password = password,
        )
        user.is_admin = True
        user.save(using=self.db)
        return user
    
class User(AbstractBaseUser):
    nickname = models.CharField(default='', max_length=128, blank=False, unique=True)
    mbti = models.CharField(default='', max_length=4)
    description = models.TextField()

    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'nickname'
    REQUIRED_FIELDS = ['mbti', 'description']

    # 관리자 사이트 접근 권한 부여를 위해 is_staff 필드 사용
    @property
    def is_staff(self):
        return self.is_admin