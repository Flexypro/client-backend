import os
from rest_framework.routers import DefaultRouter

from django.conf import settings
from .views import (
    OrderViewSet, 
    NotificationViewSet, 
    SolvedViewSet, 
    TransactionViewSet,
    ProfileViewSet,
    TokenPairViewClient,
    TokenPairViewFreelancer,
    RegisterView,
    VerifyUserAccountView,   
    ResendOTPView,
    ResetPasswordView,
    PasswordTokenCheckView,
    SetNewPasswordView,
)
from django.urls import path, include
from rest_framework_simplejwt.views import (
    # TokenObtainPairView,
    TokenRefreshView,        
)

from django.conf.urls.static import static

PREFIX = settings.API_VERSION_PREFIX

router = DefaultRouter()

router.register(f'{PREFIX}/profile', ProfileViewSet, basename='profile')
router.register(f'{PREFIX}/orders', OrderViewSet, basename='orders')
router.register(f'{PREFIX}/notifications', NotificationViewSet, basename='notifications')
router.register(f'{PREFIX}/solved', SolvedViewSet, basename='solved')
router.register(f'{PREFIX}/transactions', TransactionViewSet, basename='transactions')
urlpatterns = [
    path(f'{PREFIX}/token/c/', TokenPairViewClient.as_view(), name='token_obtain_pair'),
    path(f'{PREFIX}/token/f/', TokenPairViewFreelancer.as_view(), name='token_obtain_pair'),
    path(f'{PREFIX}/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path(f'{PREFIX}/auth/client/register/', RegisterView.as_view(), name='register'),
    path(f'{PREFIX}/verify-account/', VerifyUserAccountView.as_view(), name='verify-account'),
    path(f'{PREFIX}/resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path(f'{PREFIX}/reset-password/', ResetPasswordView.as_view(), name='reset-password' ),
    path(f'password-reset-confirm/<uidb64>/<token>/', PasswordTokenCheckView.as_view(), name='password-reset-confirm'),
    path(f'{PREFIX}/password-reset-complete/', SetNewPasswordView.as_view(), name='password-reset-complete')    
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
urlpatterns += router.urls