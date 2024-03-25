from django.urls import re_path
from .consumers import BidConsumer, CompletedConsumer, HireConsumer, OrderConsumer, ChatConsumer, NotificationConsumer, SolutionConsumer

websocket_urlpatterns = [
    re_path(r"ws/order/(?P<room_id>\w+)/$", OrderConsumer.as_asgi()),
    re_path(r"ws/chat/(?P<room_id>\w+)/$", ChatConsumer.as_asgi()),
    re_path(r"ws/notifications/(?P<room_id>\w+)/$", NotificationConsumer.as_asgi()),
    re_path(r"ws/bid/(?P<room_id>\w+)/$", BidConsumer.as_asgi()),
    re_path(r"ws/hire/(?P<room_id>\w+)/$", HireConsumer.as_asgi()),
    re_path(r"ws/solutions/(?P<room_id>\w+)/$", SolutionConsumer.as_asgi()),
    re_path(r"ws/completed/(?P<room_id>\w+)/$", CompletedConsumer.as_asgi()),
    re_path(r"ws/support/(?P<room_id>\w+)/$", CompletedConsumer.as_asgi()),
]