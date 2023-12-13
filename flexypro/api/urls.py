import os
from rest_framework.routers import DefaultRouter

from django.conf import settings
from .views import (
    OrderViewSet, 
    NotificationViewSet, 
    SolvedViewSet, 
    TransactionViewSet,
    ProfileViewSet,
    TokenPairView
)
from django.urls import path, include
from rest_framework_simplejwt.views import (
    # TokenObtainPairView,
    TokenRefreshView,    
)

from django.conf.urls.static import static

router = DefaultRouter()

router.register(f'{settings.API_VERSION_PREFIX}/profile', ProfileViewSet, basename='profile')
router.register(f'{settings.API_VERSION_PREFIX}/orders', OrderViewSet, basename='orders')
router.register(f'{settings.API_VERSION_PREFIX}/notifications', NotificationViewSet, basename='notifications')
router.register(f'{settings.API_VERSION_PREFIX}/solved', SolvedViewSet, basename='solved')
router.register(f'{settings.API_VERSION_PREFIX}/transactions', TransactionViewSet, basename='transactions')
urlpatterns = [
    path(f'{settings.API_VERSION_PREFIX}/token/', TokenPairView.as_view(), name='token_obtain_pair'),
    path(f'{settings.API_VERSION_PREFIX}/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
urlpatterns += router.urls