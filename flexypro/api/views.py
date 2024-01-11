from base64 import urlsafe_b64encode
from email import utils
import json
from django.shortcuts import redirect, render
import pyotp
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
    setNewPasswordSerializer,
    OTPSerializer,
    OTP
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

import requests
from . import utils
# from django_otp.exceptions import OTPVerificationError

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
            email_body = f'Hi {user.username}\nReset your account password with below\n{abs_url}'

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
                return redirect(f'{settings.USED_TOKEN_URL}{uidb64}/{token}')
            
            return redirect(f'{settings.PASSWORD_RESET_URL}{uidb64}/{token}')
                        
            # return Response({
            #     'success':True,
            #     'uidb64':user.id,
            #     'token':token
            # })
            
        except DjangoUnicodeDecodeError as error:
            return redirect(f'{settings.BAD_TOKEN_URL}{uidb64}/{token}')

class SetNewPasswordView(generics.GenericAPIView):
    serializer_class = setNewPasswordSerializer

    def put(self, request):
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
        # user = request.data
        # print(user)
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])

        topt = pyotp.TOTP(settings.OTP_KEY)

        otp = Util.generate_otp(topt)

        OTP.objects.create(
            otp = otp,
            user = user
        )

        # user.save()

        # token = RefreshToken.for_user(user).access_token

        # current_site = get_current_site(request).domain
        # relative_link = reverse('verify-email')
        # abs_url = f'http://{current_site+relative_link+"?token="+str(token)}'
        email_body = f'Hi {user.username} \nYour OTP is {otp}'

        data = {
            'email_body':email_body,
            'email_subject':'Email Verification',
            'email_to': user.email
        }

        Util.send_email(data=data)

        return Response(user_data, status=status.HTTP_201_CREATED)
    
class CreateCheckoutOrderView(generics.GenericAPIView):

    def post(self, request):  
        try:   
            order_id = request.data['orderId']
            order = Order.objects.get(id=order_id)        
            amount = order.amount
            access_token = utils.get_token()

            # Create order
            order = utils.create_order(amount=amount, access_token=access_token)
            id = order['id']
            return Response({
                'id':id
            }, status=status.HTTP_200_OK)
        except:
            return Response({
                'error':'Error while creating payment'
            }, status=status.HTTP_400_BAD_REQUEST)

class CapturePaymentView(generics.GenericAPIView):
    def post(self, request):
        try:
            paypalId = request.data['paypalId']
            orderId = request.data['orderId']
            order = Order.objects.get(id=orderId)
            access_token = utils.get_token()
            paypal_id, amount_value, paypal_fee_value, net_amount_value, currency_code, status_value = utils.capture_payment(paypalId, access_token)

            # Create transaction
            Transaction.objects.create(
                paypal_id = paypal_id,
                order = order,
                status = status_value,
                amount_value = amount_value,
                paypal_fee_value = paypal_fee_value,
                net_amount_value = net_amount_value,
                currency_code = currency_code,
                channel = 'Paypal',            
            )

            # Modify order to paid true
            if not order.paid:
                order.paid = True
                order.save()

            return Response({
                'success':'Purchase complete'
            }, status=status.HTTP_200_OK)
        
        except:
            return Response({
                'error':'Error occured during transaction'
            }, status=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:            

            user = User.objects.get(username=self.request.user)

            if not user.is_verified:
                topt = pyotp.TOTP(settings.OTP_KEY)

                otp = Util.generate_otp(topt)

                OTP.objects.create(
                    otp = otp,
                    user = user
                )

                email_body = f'Hi {user.username} \nYour OTP is {otp}'

                data = {
                    'email_body':email_body,
                    'email_subject':'Email Verification',
                    'email_to': user.email
                }

                Util.send_email(data=data)

                return Response({
                    'success':'OTP resend successfully'
                },status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'detail':'User already verified'
                },status=status.HTTP_400_BAD_REQUEST)
        
        except Exception:
            return Response({
                'error': 'Invalid request'
            }, status=status.HTTP_400_BAD_REQUEST)

class VerifyUserAccountView(generics.GenericAPIView):
    serializer_class = OTPSerializer
    permission_classes = [IsAuthenticated]

    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        print(serializer.validated_data)

        otp = serializer.validated_data['otp']
        
        print(self.request.user)

        user = User.objects.get(username=self.request.user)
        otp_object = OTP.objects.filter(user=user).last()

        print(otp_object)

        # print(f'Token found {token}')                
            # payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            # user = User.objects.get(id=payload['user_id'])
        try:
            if not user.is_verified:
                valid = Util.verify_otp(self, otp, otp_object)
                print("--->",valid)
                
                if valid:
                    if not user.is_verified:
                        user.is_verified = True
                        otp_object.used = True
                        otp_object.save()
                        user.save()
                        return Response({
                            'success':'Account activation success'
                        }, status=status.HTTP_200_OK)
                elif otp != otp_object.otp:
                    print(otp_object.otp)
                    return Response({
                        'error':'Invalid OTP'
                    }, status=status.HTTP_400_BAD_REQUEST)
                elif otp_object.used:
                    return Response({
                        'error':'OTP already used'
                    }, status.HTTP_400_BAD_REQUEST)                       
            else:
                return Response({
                'error':'User already verified'
                }, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception:
            return Response({
                    'error':'No OTPs found'
                }, status.HTTP_400_BAD_REQUEST) 
        # except jwt.ExpiredSignatureError as error:            
            # return redirect(f'{settings.APP_HOME}/request-newtoken')
            # return Response({
            #     'error':'Activation link expired'
            # }, status=status.HTTP_400_BAD_REQUEST)        
        
        # except jwt.exceptions.DecodeError as error:
        #     # return redirect(f'{settings.APP_HOME}/request-newtoken')
        #     return Response({
        #         'error':'Invalid Token',
        #     }, status=status.HTTP_400_BAD_REQUEST)

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