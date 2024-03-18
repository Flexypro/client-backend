from django.urls import re_path
from .consumers import BidConsumer, OrderConsumer, ChatConsumer, NotificationConsumer

websocket_urlpatterns = [
    re_path(r"ws/order/(?P<room_id>\w+)/$", OrderConsumer.as_asgi()),
    re_path(r"ws/chat/(?P<room_id>\w+)/$", ChatConsumer.as_asgi()),
    re_path(r"ws/notifications/(?P<room_id>\w+)/$", NotificationConsumer.as_asgi()),
    re_path(r"ws/bid/(?P<room_id>\w+)/$", BidConsumer.as_asgi()),
    
]