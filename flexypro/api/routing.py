from django.urls import re_path
from .consumers import OrderConsumer

websocket_urlpatterns = [
    re_path(r"ws/order/(?P<room_id>\w+)/$", OrderConsumer.as_asgi())
]