from django.dispatch import receiver
from django.db.models.signals import post_save, pre_save
from .models import Order, Notification, Chat
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import User

@receiver(post_save, sender=Order)
def create_notification_new_order(instance, created, **kwargs):
    if created:
        writer = User.objects.get(username='mucia')
        try:
            # Create notification for writer
            Notification.objects.create(
                user = writer,
                message=f'New order - {instance.title}, was created. Check order ASAP',
                order = instance
            )

            # Create notification for client
            Notification.objects.create(
                user = instance.client.user,
                message=f'You created a new order - {instance.title}',
                order = instance
            )
        except ObjectDoesNotExist:
            pass

@receiver(pre_save, sender=Order)
def create_notification_instruction_update(instance, **kwargs):
    writer = User.objects.get(username='mucia')
    try:
        old_order = Order.objects.get(pk=instance.pk)
        if old_order.instructions != instance.instructions:
            Notification.objects.create(
                user = writer,
                message=f'Order - {instance.title}, instructions were updated. ',
                order = instance
            )
        if old_order.status != instance.status and (
            instance.status == 'completed'
        ):
            Notification.objects.create(
                user = writer,
                message=f'Order - {instance.title}, was completed. ',
                order = instance
            )
    except:
        pass

@receiver(post_save, sender=Chat)
def create_notification_chat(instance, **kwargs):
    try:
        receiver = instance.receiver
        sender = instance.sender
        Notification.objects.create(
            user = receiver,
            message = f'You have unread messages from {sender}'
        )
    except:
        pass