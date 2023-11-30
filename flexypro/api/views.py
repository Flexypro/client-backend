from django.shortcuts import render
from rest_framework import viewsets
from .models import Order, Client, Notification, Solved, Chat, User
from .serializers import (
    OrderSerializer, 
    NotificationSerializer, 
    SolvedSerializer,
    ChatSerializer
)
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from .permissions import IsOwner
from rest_framework.decorators import action

# Create your views here.
class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'post', 'update']

    def perform_create(self, serializer):
        user = self.request.user
        client = Client.objects.get(user = user)
        serializer.save(client=client)

    def get_queryset(self):
        user = self.request.user
        if user.is_staff:
            return Order.objects.all()
        client = Client.objects.get(user = user)
        return Order.objects.filter(client=client)

    def get_object(self):
        order_id = self.kwargs.get('pk')
        queryset = self.filter_queryset(self.get_queryset())

        try:
            obj = queryset.get(id=order_id)
            self.check_object_permissions(self.request, obj)
            return obj
        except:
            raise NotFound("The order was not Found")

    def update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return super().update(request, *args, **kwargs)      

    @action(detail=True, methods=['get'], url_path='all-chats')
    def order_chats(self, request, pk=None):
        order = self.get_object()
        chats = Chat.objects.filter(order=order)
        serializer = ChatSerializer(chats, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'], url_path='create-chat')
    def create_chat(self, request, pk=None):
        order = self.get_object()
        sender = request.user
        
        receiver = User.objects.get(username='mucia')
        
        if sender.is_staff:
            receiver = order.client.user

        else:
            status.HTTP_400_BAD_REQUEST

        serializer = ChatSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(
                order=order,
                sender = sender,
                receiver = receiver
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # Next feature
    # @action(detail=True, methods=['delete'], url_path='destroy-chat')
    # def destroy_chat(self, request, pk=None):
    #     order = self.get_object()
    #     if request.user:
    #         Chat.objects.filter(order=order)

class NotificationViewSet(viewsets.ModelViewSet):    
    queryset = Notification.objects.all()
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ['get']

    def get_queryset(self):
        user = self.request.user        
        return self.queryset.filter(user=user)
    
'''--------------------------To be implemented fully--------------------------------'''

class SolvedViewSet(viewsets.ModelViewSet):
    queryset = Solved.objects.all()
    serializer_class = SolvedSerializer

    def get_object(self):
        order_id = self.kwargs.get('pk')
        queryset = self.filter_queryset(self.get_queryset())

        try:
            obj = queryset.get(id=order_id)
            self.check_object_permissions(self.request, obj)
            return obj
        except:
            raise NotFound("The order was not Found")