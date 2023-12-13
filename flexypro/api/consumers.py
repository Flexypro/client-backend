import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import User
from .models import Order

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
        print("Trying to connect to notifications")
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
        print(message)
        await self.send(text_data=json.dumps({
            'type':'new_notification',
            'message':message
        }))



        # print(f'Room name => {self.room_id}\nRoom group => {self.room_group_name}')
    
    # async def disconnect(self, code):
    #     await (self.channel_layer.group_discard)(
    #         self.room_group_name, self.channel_name
    #     )
    #     return super().disconnect(code)
    
    # async def receive(self, text_data):
    #     data = json.loads(text_data)
    #     message_type = data.get('type')

    #     if message_type == 'new.order':
    #         self.room_name = data.get('room_name')
    #         print(self.room_name)
    #         await self.channel_layer.group_add(
    #             self.room_name, self.channel_name
    #         )
    
    # async def receive(self, text_data=None, bytes_data=None):
    #     text_data_json = await json.loads(text_data)
    #     message = await text_data_json['message']
    #     print(message)

    #      # Send message to room group
    #     await async_to_sync(self.channel_layer.group_send)(
    #         self.room_group_name, {"type": "chat.message", "message": message}
    #     )
