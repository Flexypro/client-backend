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
    VerifyUserEmail,
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
    path(f'verify-email/', VerifyUserEmail.as_view(), name='verify-email')
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
urlpatterns += router.urls