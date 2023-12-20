from base64 import urlsafe_b64encode
from django.shortcuts import redirect, render
from rest_framework import viewsets
from .models import (
    Order, 
    Client, 
    Notification, 
    Solved, 
    Chat, 
    User, 
    Transaction, 
    Solution,
    Profile,
    Freelancer,    
    )
from .serializers import (
    OrderSerializer, 
    NotificationSerializer, 
    SolvedSerializer,
    ChatSerializer,
    TransactionSerializer, 
    SolutionSerializer,
    ProfileSerializer,
    ObtainTokenSerializerClient,    
    ObtainTokenSerializerFreelancer,    
    RegisterSerializer,
    ResetPasswordSerializer,
    setNewPasswordSerializer
)

from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from .permissions import IsOwner
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
from django.db.models import Q
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
import jwt

# Create your views here.

class ResetPasswordView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    def post(self, request):
        data={
            'request':request,
            'data': request.data
        }
        serializer = self.serializer_class(data=data)

        email = request.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_b64encode(bytes(str(user.id), 'utf-8')).decode('utf-8')
            # uidb64 = user.id

            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request).domain
            relative_link = reverse(
                'password-reset-confirm', kwargs={
                    'uidb64':uidb64,
                    'token':token
                }
            )
            abs_url = f'http://{current_site+relative_link}'
            email_body = f'Hi {user.username} Reset your account password with below \n {abs_url}'

            data = {
                'email_body':email_body,
                'email_subject':'Password Reset',
                'email_to': user.email
            }

            Util.send_email(data)
        
            return Response({
                    f'success':'Password reset send to {email}',
                }, status=status.HTTP_200_OK
            )
        return Response({
            'error':'No user with the provided email found'
        }, status=status.HTTP_404_NOT_FOUND)

class PasswordTokenCheckView(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({
                    'error':'Token already used'
                })
                        
            return Response({
                'success':True,
                'uidb64':user.id,
                'token':token
            })
            
        except DjangoUnicodeDecodeError as error:
            return Response({
                'error':'Invalid token'
            })

class SetNewPasswordView(generics.GenericAPIView):
    serializer_class = setNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)

        serializer.is_valid(raise_exception=True)

        return Response({
            'success':True,
            'message':'Password reset successful'
        }, status=status.HTTP_200_OK)

class TokenPairViewClient(TokenObtainPairView):
    permission_classes = [AllowAny]
    serializer_class = ObtainTokenSerializerClient

class TokenPairViewFreelancer(TokenObtainPairView):
    permission_classes = [AllowAny]
    serializer_class = ObtainTokenSerializerFreelancer

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    # permission_classes = (AllowAny)
    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])

        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        relative_link = reverse('verify-email')
        abs_url = f'http://{current_site+relative_link+"?token="+str(token)}'
        email_body = f'Hi {user.username} Verify your account using the link below \n {abs_url}'

        data = {
            'email_body':email_body,
            'email_subject':'Email Verification',
            'email_to': user.email
        }

        Util.send_email(data=data)

        return Response(user_data, status=status.HTTP_201_CREATED)

class VerifyUserEmailView(generics.GenericAPIView):
    
    def get(self,request):
        token = request.GET.get('token')
        print(f'Token found {token}')
                
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
                print("Account activated")

                return redirect(settings.APP_HOME)            
            return redirect(settings.APP_HOME) 
        except jwt.ExpiredSignatureError as error:            
            # return redirect(f'{settings.APP_HOME}/request-newtoken')
            return Response({
                'error':'Activation link expired'
            }, status=status.HTTP_400_BAD_REQUEST)        
        
        except jwt.exceptions.DecodeError as error:
            # return redirect(f'{settings.APP_HOME}/request-newtoken')
            return Response({
                'error':'Invalid Token',
            }, status=status.HTTP_400_BAD_REQUEST)

class ProfileViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ['get','put']

    def update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return super().update(request, *args, **kwargs)
    
    def get_queryset(self):
        current_user = self.request.user
        return self.queryset.filter(user=current_user)

class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'post', 'update', 'put']

    def create(self, request, *args, **kwargs):        
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():   
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        else:
            print(serializer.errors)
            return Response(serializer.data, status=status.HTTP_400_BAD_REQUEST)

    def perform_create(self, serializer):
        user = self.request.user
        client = Client.objects.get(user = user)
        freelancer = Freelancer.objects.all()[0]
        serializer.save(client=client, freelancer=freelancer)

    def get_queryset(self):
        user = self.request.user
        query = Q(client__user=user) | Q(freelancer__user=user)
            
        return Order.objects.filter(query).order_by('-updated')

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

        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            "chat_lobby", {
                "type":"chat.message",
                "message":"Order Compeleted"
            }
        )
        return super().update(request, *args, **kwargs)

    @action(detail=True, methods=['get'], url_path='solution')
    def get_solution(self, request, pk=None):
        order = self.get_object()
        solution = Solution.objects.filter(order=order)
        serializer = SolutionSerializer(solution, many=True)
        return Response(serializer.data)
    
    # @action(detail=True, methods=['post'], url_path='create-solution')
    @get_solution.mapping.post
    def post_solution(self, request, pk=None):
        order = self.get_object()
        parser_classes = (MultiPartParser, FormParser)
        serializer = SolutionSerializer(data=request.data, context={'request': request})        
        if serializer.is_valid():
            serializer.save(
                order=order,                
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)    

    @action(detail=True, methods=['get'], url_path='chats')
    def order_chats(self, request, pk=None):
        order = self.get_object()
        chats = Chat.objects.filter(order=order)
        serializer = ChatSerializer(chats, many=True)
        return Response(serializer.data)
    
    # @action(detail=True, methods=['post'], url_path='create-chat')
    @order_chats.mapping.post
    def create_chat(self, request, pk=None):
        order = self.get_object()
        sender = request.user
        receiver = order.client.user

        client = order.client.user
        freelancer = order.freelancer.user

        if sender == client:
            receiver = freelancer

        serializer = ChatSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(
                order=order,
                sender = sender,
                receiver = receiver
            )            

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class NotificationViewSet(viewsets.ModelViewSet):    
    queryset = Notification.objects.all()
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ['get','put']

    def update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return super().update(request, *args, **kwargs)

    def get_queryset(self):
        user = self.request.user        
        return self.queryset.filter(user=user).order_by('-created_at')

class TransactionViewSet(viewsets.ModelViewSet):
    queryset = Transaction.objects.all()
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ['get']

    def get_queryset(self):
        user = self.request.user

        if user.is_staff:    
            return self.queryset.filter(to=user)  

        client = Client.objects.get(user=user)
        return self.queryset.filter(_from=client).order_by('-timestamp')

def new_order_created(order_instance, client, freelancer):
    serialized_data = OrderSerializer(order_instance).data
    response_data = {
        "order":serialized_data
    }

    channel_layer = get_channel_layer()
    client_room_id = client.id
    freelancer_room_id = freelancer.id
    
    async def send_order():

        freelancer_room = f'order_{freelancer_room_id}' 
        client_room = f'order_{client_room_id}'  

        print(f'Senfing to Client {client_room} , Writer {freelancer_room}') 

        try:
        # Sending order to freelancer
            await channel_layer.group_send(
                freelancer_room, {
                    'type':'new.order',
                    'message':response_data
                }
            )

            # Sending order to client (owner)
            await channel_layer.group_send(
                client_room, {
                    'type':'new.order',
                    'message':response_data
                }
            )
        except Exception as e:
            print("Error => ", e)


    async_to_sync(send_order)()
    return Response(response_data) 

def send_message_signal(receiver, sender, instance):

    serialized_data = ChatSerializer(instance).data
    serialized_data['order'] = str(serialized_data['order'])
    response_data = {
        'sent_message':serialized_data
    }

    channel_layer = get_channel_layer()

    room_name = f'chat_{receiver.id}'

    async def send_message():
        try:
            await channel_layer.group_send(
                room_name, {
                    'type': 'new.chat',
                    'message': response_data
                }
            )
        except Exception as e:
            print("Error => ", e)

    async_to_sync(send_message)()
    return Response(response_data) 

def send_alert(instance, user):
    channel_layer = get_channel_layer()
    room_name  =f'notifications_{user.id}'

    serialized_data = NotificationSerializer(instance).data
    response_data = {
        'notification':serialized_data
    }

    async def send_notification():
        try:
            await channel_layer.group_send(
                room_name, {
                    'type':'new.notification',
                    'message':response_data
                }
            )
        except Exception as e:
            print("Error => ", e)
    
    async_to_sync(send_notification)()
    return Response(response_data)

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