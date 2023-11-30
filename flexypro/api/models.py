from django.db import models
from django.contrib.auth.models import User
import uuid

# Create your models here.
class Client(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    def __str__(self) -> str:
        return (str(self.user))

class Solved(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=80)
    amount = models.FloatField()
    category = models.CharField(max_length=20)  

    def __str__(self) -> str:
        return str(self.title)

class Order(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, blank=True, null=True)
    title = models.CharField(max_length=80)
    category = models.CharField(max_length=20)
    deadline = models.DateTimeField()
    instructions = models.TextField()
    status_choices = [
        ('in_progress','In Progress'),
        ('completed','Completed')
    ]
    status = models.CharField(max_length=20, choices=status_choices, default='in_progress')
    amount = models.FloatField()
    created = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self) -> str:
        return str(self.title)

class Rating(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    order = models.OneToOneField(Order, on_delete=models.CASCADE)
    rating = models.FloatField(blank=True,null=True)
    message = models.CharField(max_length=150, blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True, null=True)


    def __str__(self) -> str:
        return str(self.rating) + str(self.order)

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=40)
    last_name = models.CharField(max_length=40)

    def __str__(self) -> str:
        return str(self.user)

class Chat(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    order = models.ForeignKey(Order, related_name='order', on_delete=models.CASCADE, null=True, blank=True)
    sender = models.ForeignKey(User, related_name='sender', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='receiver', on_delete=models.CASCADE)    
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return str(str(self.sender) + ' to ' +str(self.receiver))

# class Chat(models.Model):
#     message = models.TextField()
#     sender = models.ForeignKey(User, on_delete=models.CASCADE,)
#     receiver = models.ForeignKey( User, on_delete=models.CASCADE,)
#     created_at = models.DateTimeField(auto_now_add=True)
#     status = models.BooleanField(default=False)

#     def __str__(self):
#         return str(self.sender) + 'message'
    
class Notification(models.Model):
    # id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.CharField(max_length=250)
    created_at = models.DateTimeField(auto_now_add=True)
    order = models.ForeignKey(Order, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self) -> str:
        return str(self.user) + ' - notification'