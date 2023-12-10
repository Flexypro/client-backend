from django.dispatch import receiver
from django.db.models.signals import post_save, pre_save
from .models import (
    Order, 
    Notification, 
    Chat, 
    Transaction, 
    Solution, 
    Profile
)
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import User
from .views import new_order_created

@receiver(post_save, sender=User)
def create_profile(instance, created, **kwargs):
    if created:
        try:
            Profile.objects.create(
                user = instance,            
            )
        except:
            pass

@receiver(post_save, sender=Order)
def create_notification_new_order(instance, created, **kwargs):
    if created:
        writer = User.objects.get(username='mucia')
        client = User.objects.get(username=instance.client.user)
        # cliemt = 
        try:
            # Create notification for writer when order is created
            Notification.objects.create(
                user = writer,
                message=f'New order - {instance.title}, was created. Check order ASAP',
                order = instance
            )

            # Create notification for client when order is created
            Notification.objects.create(
                user = instance.client.user,
                message=f'You created a new order - {instance.title}',
                order = instance
            )

            new_order_created(instance, client, writer)
            
        except ObjectDoesNotExist:
            pass

@receiver(pre_save, sender=Order)
def order_notification_update(instance, **kwargs):
    writer = User.objects.get(username='mucia')
    try:
        old_order = Order.objects.get(pk=instance.pk)

        # Create notification for writer on updated instructions
        if old_order.instructions != instance.instructions:
            Notification.objects.create(
                user = writer,
                message=f'Order - {instance.title}, instructions were updated. ',
                order = instance
            )

        # Create notification for writer on completed order
        if old_order.status != instance.status and (
            instance.status == 'completed'
        ):
            
            Notification.objects.create(
                user = writer,
                message=f'Order - {instance.title}, was completed. ',
                order = instance
            )            
            
            Transaction.objects.create(
                to = writer,
                _from = instance.client,
                amount = instance.amount,
                order = instance             
            )

        # Create notification for new attachment
        if old_order.attachment != instance.attachment and instance.attachment:
            Notification.objects.create(
                user = writer,
                message =  f'There were new attachment for order - {instance.title}',
                order = instance
            )            

    except:
        pass

@receiver(post_save, sender=Chat)
def create_notification_chat(instance, **kwargs):
    try:
        # Create notification for new messages
        receiver = instance.receiver
        sender = instance.sender
        Notification.objects.create(
            user = receiver,
            message = f'You have unread messages from {sender}',
            order = instance.order
        )
    except:
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
    except:
        pass