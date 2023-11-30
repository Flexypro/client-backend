from rest_framework.routers import DefaultRouter
from .views import OrderViewSet, NotificationViewSet, SolvedViewSet
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
router = DefaultRouter()

router.register('orders', OrderViewSet, basename='orders')
router.register('notifications', NotificationViewSet, basename='notifications')
router.register('solved', SolvedViewSet, basename='solved')

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]

urlpatterns += router.urls