import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
# from django.contrib.auth.models import User

from .models import Order, User

# class NewOrderCreated

class OrderConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['room_id']

        if self.room_id:
            self.room_group_name = f"order_{self.room_id}"
            await (self.channel_layer.group_add)(
                self.room_group_name, self.channel_name
            )
            await self.accept()

            print("[WS] Order socket connected")
        
        else:
            await self.close()
        
        # self.user = self.scope['user']                

        # Join room group    
    async def new_order(self, event):
        message = event["message"]

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'type':'new_order',
            "message": message
        }))
    
class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['room_id']

        if self.room_id:
            self.room_group_name = f'chat_{self.room_id}'
            await self.channel_layer.group_add(
                self.room_group_name, self.channel_name
            )
            await self.accept()
            print("[WS] Message socket connected")

        else:
            await self.close()

    async def receive(self, text_data):
        data = json.loads(text_data)
        if data['receiver']:
            receiver = data['receiver']
            receiver_id = await self.get_receiver_id(receiver)
            order_id = data['orderId']
            room_name = f'chat_{receiver_id}'

            await self.channel_layer.group_send(
                room_name, {
                    'type': 'typing.status',
                    'message': {
                        'typing':True,
                        'order_id':order_id
                    }
                }
            )    
        
    async def typing_status(self, event):
        message = event['message']
        await self.send(text_data=json.dumps({
            'type':'typing_status',
            'message':message
        }))    

    @database_sync_to_async
    def get_receiver_id(self, receiver):
        return User.objects.get(username=receiver).id

    async def new_chat(self, event):
        message = event["message"]

        # Send message WS
        await self.send(text_data=json.dumps({
            'type':'new_message',
            'message':message
        }))

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['room_id']
        if self.room_id:
            self.room_group_name = f'notifications_{self.room_id}'
            await self.channel_layer.group_add(
                self.room_group_name, self.channel_name
            )
            await self.accept()
            print('[WS] Notification socket connected')
        else:
            await self.close()
    
    async def new_notification(self, event):
        message = event['message']
        await self.send(text_data=json.dumps({
            'type':'new_notification',
            'message':message
        }))

class BidConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['room_id']   
        if self.room_id:
            self.room_group_name = f'bids_{self.room_id}' 
            await self.channel_layer.group_add(
                self.room_group_name, self.channel_name
            )    
            await self.accept()
            print('[WS] Bid socket connected')
    async def new_bid(self, event):
        message = event['message']
        await self.send(text_data=json.dumps({
            'type': "new_bid",
            'message': message
        }))
        
class HireConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['room_id']   
    
        if self.room_id:
            self.room_group_name = f'hire_{self.room_id}' 
            await self.channel_layer.group_add(
                self.room_group_name, self.channel_name
            )    
            await self.accept()
            print('[WS] Hire socket connected')
            
    async def hire_order(self, event):
        message = event['message']
        await self.send(text_data=json.dumps({
            'type':'hire_order',
            'message':message
        }))
        
class SolutionConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['room_id']   
        if self.room_id:
            self.room_group_name = f'solutions_{self.room_id}' 
            await self.channel_layer.group_add(
                self.room_group_name, self.channel_name
            )    
            await self.accept()
            print('[WS] Solutions socket connected')
            
    async def new_solutions(self, event):
        
        message = event['message']
        await self.send(text_data=json.dumps({
            'type':'new_solution',
            'message':message
        }))
        
class CompletedConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['room_id']   
        if self.room_id:
            self.room_group_name = f'completed_{self.room_id}' 
            await self.channel_layer.group_add(
                self.room_group_name, self.channel_name
            )    
            await self.accept()
            print('[WS] Completed socket connected')
    async def completed_order(self, event):
        message = event['message']
        await self.send(text_data=json.dumps({
            'type': "completed",
            'message': message
        }))

class SupportChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['room_id']   
        if self.room_id:
            self.room_group_name = f'support_{self.room_id}' 
            await self.channel_layer.group_add(
                self.room_group_name, self.channel_name
            )    
            await self.accept()
            print('[WS] Support socket connected')
    async def support_chat(self, event):
        message = event['message']
        print("[WS] Sending chat")
        await self.send(text_data=json.dumps({
            'type': "support",
            'message': message
        }))