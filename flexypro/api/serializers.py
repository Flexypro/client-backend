from rest_framework import serializers
from .models import (
    Order, 
    Client, 
    Notification, 
    Rating, 
    Solved,
    Chat
)
from django.contrib.auth.models import User
from rest_framework import permissions

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = [
            'username',
        ]

class ClientSerializer(serializers.ModelSerializer):
    user = UserSerializer(serializers.ModelSerializer)
    
    class Meta:
        model = Client
        exclude = ['id']

class RatingSerializer(serializers.ModelSerializer):

    class Meta:
        model = Rating
        fields = [
            'rating'
        ]

class OrderSerializer(serializers.ModelSerializer): 
    # user = UserSerializers(source='user_set', many=True, read_only=True)
    client = ClientSerializer(read_only=True)
    rating = RatingSerializer(read_only=True)

    class Meta:
        model = Order
        fields = '__all__'

class NotificationSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Notification
        fields = '__all__'

class SolvedSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Solved
        fields = '__all__'

class ChatSerializer(serializers.ModelSerializer):
    sender = UserSerializer(read_only=True)
    receiver = UserSerializer(read_only=True)
    class Meta:
        model = Chat
        fields = '__all__'