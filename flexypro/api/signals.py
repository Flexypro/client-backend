from django.dispatch import receiver
from django.db.models.signals import post_save, pre_save, pre_delete
from .models import (
    Order, 
    Notification, 
    Chat,
    SupportChat, 
    Transaction, 
    Solution, 
    Profile, 
    Freelancer,
    User,
    Bid,
)
from .serializers import OrderSerializer
from django.core.exceptions import ObjectDoesNotExist
# from django.contrib.auth.models import User
from .views import new_order_created, new_support_message, send_alert, send_alert_completed, send_alert_order, send_alert_solution, send_bidding_delete, send_message_signal, send_bidding_add

@receiver(post_save, sender=User)
def create_profile(instance, created, **kwargs):
    if created:
        try:
            Profile.objects.create(
                user = instance,            
            )
        except:
            print("Error creating user profile")

@receiver(post_save, sender=Bid)
def create_notification_bid(instance, created, **kwargs):
    if created:
        order = instance.order
        serializer = OrderSerializer(order)
        serializer_data = serializer.data

        if serializer_data['total_bids'] == 1:
            try:
                user = instance.client.user
                Notification.objects.create(
                    user = user,
                    message = f'Your order, {instance.order.title}, has new bids',
                    order = order
                )
            except Exception as e:
                print("Error=>....> ", e)
        user = instance.client.user
        send_bidding_add(instance, user)

@receiver(pre_delete, sender=Bid)
def create_notification_delete_bid(instance,**kwargs):
    user = instance.client.user
    order = instance.order
    title  = instance.order.title
    status = instance.order.status
    
    try:
        if status == "Available":
            Notification.objects.create(
                user=user,
                message = f'Bid for order, {title}, has been deleted by the freelancer',
                order=order
            )
    except Exception as e:
        print(e)
    
    send_bidding_delete(instance, user)

@receiver(post_save, sender=Order)
def create_notification_new_order(instance, created, **kwargs):
    if created:
        client = User.objects.get(username=instance.client.user)
        new_order_created(instance, client)
        
#         try:
#             # Create notification for freelancer when order is created

#             # Notification.objects.create(
#             #     user = freelancer,
#             #     message=f'New order - {instance.title}, was created. Check order ASAP',
#             #     order = instance
#             # )

#             # Create notification for client when order is created
#             Notification.objects.create(
#                 user = instance.client.user,
#                 message=f'You created a new order - {instance.title}',
#                 order = instance
#             )
            
#         except ObjectDoesNotExist:
#             print("Error occured creating notification")

@receiver(pre_save, sender=User)
def account_activation(instance, **kwargs):
    try:
        old_instance = User.objects.get(pk=instance.pk)
        is_active_old = old_instance.is_verified
    except User.DoesNotExist:
        is_active_old = False
        print("User not verified")        

    print("Account activation success")
    if is_active_old != instance.is_verified and (
        is_active_old == False and instance.is_verified == True
    ): Notification.objects.create(
        user = instance,
        message=f'Congratulations. You activated your Gigitise account. You can now create tasks with us.'
    )

@receiver(pre_save, sender=Order)
def order_notification_update(instance, **kwargs):
    writer = instance.freelancer
    if writer is not None:
        writer_receiver = User.objects.get(username=writer.user)
    else:
        writer_receiver = None
    if writer:
        try:
            old_order = Order.objects.get(pk=instance.pk)

            if old_order.status == 'Available' and (
                instance.status == 'In Progress'
            ):
                Notification.objects.create(
                    user = writer_receiver,
                    message = f'Your bid for order, {instance.title}, has been accepted! Start working ASAP',
                    order = instance
                )
                
                send_alert_order(instance, writer_receiver)

            # Create notification for writer on updated instructions
            if old_order.instructions != instance.instructions:
                Notification.objects.create(
                    user = writer_receiver,
                    message=f'Order - {instance.title}, instructions were updated. ',
                    order = instance
                )

            # Notification for paid order to writer
            if old_order.paid != instance.paid and (
                instance.paid == True
            ):
                Notification.objects.create(
                    user=writer_receiver,
                    message=f'Congratulations! Your order {instance.title} has been paid by the client.',
                    order = instance
                )

            # Create notification for writer on completed order
            if old_order.status != instance.status and (
                instance.status == 'Completed'
            ):
                Notification.objects.create(
                    user = writer_receiver,
                    message=f'Order - {instance.title}, was completed. ',
                    order = instance
                )
                send_alert_completed(instance, writer_receiver)

            # Create notification for new attachment
            if old_order.attachment != instance.attachment and instance.attachment:
                Notification.objects.create(
                    user = writer_receiver,
                    message =  f'There were new attachment for order - {instance.title}',
                    order = instance
                )            

        except Exception as e:
            print("[Signal Error] ", e)

@receiver(post_save, sender=Chat)
def create_notification_chat(instance, **kwargs):
    try:
        # Create notification for new messages
        receiver = instance.receiver
        sender = instance.sender

        send_message_signal(receiver, sender, instance)

        Notification.objects.create(
            user = receiver,
            message = f'You have unread messages from {sender}',
            order = instance.order
        )

    except Exception as e:
        print("Error => ", e)
        pass

@receiver(post_save, sender=Solution)
def create_notification_solution(instance, **kwargs):
    client = instance.order.client
    user = User.objects.get(username=client)

    # Create notification to client for uploaded work
    try:
        Notification.objects.create(
            user = user,
            message = f'Solution for your order - {instance.order.title}, has been uploaded.',
            order = instance.order
        )
        
        send_alert_solution(instance, client)
    except Exception as e:
        print("Error => ",e)

@receiver(post_save, sender=Notification)
def notification_send_alert(instance, **kwargs):
    user = instance.user
    send_alert(instance, user)

@receiver(post_save, sender=SupportChat)
def support_new_message(instance, **kwargs):
    try:
        receiver = instance.receiver
        new_support_message(receiver, instance)
    except Exception as e:
        print("[Signal] ", e)