from rest_framework import serializers
from .models import (
    Order, 
    Client, 
    Notification, 
    Rating, 
    Solved,
    Chat, 
    Transaction,
    Solution,
    Profile,
    Freelancer,
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

class FreelancerSerializer(serializers.ModelSerializer):
    user = UserSerializer(serializers.ModelSerializer)
    
    class Meta:
        model = Freelancer
        exclude = ['id']

class RatingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rating
        fields = [
            'rating'
        ]

class SolutionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Solution
        fields = [
            'solution', '_type','created'
        ]  

class OrderSerializer(serializers.ModelSerializer): 
    client = ClientSerializer(read_only=True)
    freelancer = FreelancerSerializer(read_only=True)
    solution = SolutionSerializer(read_only=True)
    rating = RatingSerializer(read_only=True)

    class Meta:
        model = Order
        fields = '__all__'
    
    # def get_solution(self,obj):
    #     return obj.solution

class NotificationSerializer(serializers.ModelSerializer):
    user = serializers.CharField(source='user.username', read_only=True)
    order_id = serializers.CharField(source='order.id', read_only=True)    

    class Meta:
        model = Notification
        fields = ['id','user','message', 'order_id', 'read_status', 'created_at']
        ordering = ['-created_at']

class ProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username',read_only=True)
    notification_count = serializers.SerializerMethodField()
    # orders_count = serializers.SerializerMethodField()
    unread_notifications = serializers.SerializerMethodField()

    class Meta:
        model = Profile
        fields = [
            'id',
            'username', 
            'first_name', 
            'last_name', 
            'notification_count', 
            'unread_notifications',
            # 'orders_count', 
            'bio', 
            'profile_photo'
        ]
        
    def get_notification_count(self, profile):
        user = profile.user        
        notification_count = Notification.objects.filter(user=user).count()
        return notification_count

    def get_unread_notifications(self, profile):
        user = profile.user
        unread_notifications = Notification.objects.filter(user=user, read_status=False).count()
        return unread_notifications

    # def get_orders_count(self, profile):
    #     user = profile.user
    #     client = Client.objects.get(user=user)        
    #     orders_count = Order.objects.filter(client=client).count()
    #     return orders_count
    
    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['last_login'] = instance.user.last_login
        return data


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

class TransactionSerializer(serializers.ModelSerializer):
    _from = ClientSerializer(read_only=True)
    to = UserSerializer(read_only=True)
    class Meta:
        model = Transaction
        fields = '__all__'