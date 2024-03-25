from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin
)
from django.conf import settings
import uuid
# Create your models here.

class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None):
        if username is None:
            raise TypeError("Username required")
        if email is None:
            raise TypeError("Password is required")
        
        user = self.model(
            username = username,
            email = self.normalize_email(email)
        )
        user.set_password(password)
        user.save()
        return user
    
    def create_superuser(self, username, email, password):
        if password is None:
            raise TypeError('Password required')

        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user

class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    first_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255, blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now = True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    objects = UserManager()

    def __str__(self) -> str:
        return str(self.username)

class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)    
    otp = models.CharField(max_length=6, blank=True, null=True)
    used = models.BooleanField(default=False)
    # timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f'{self.otp}' + f' {str(self.user)}'
    
class Client(models.Model):
    payment_choices = (
        ('Paypal', 'Paypal'),
        ('Stripe', 'Stripe'),
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email_uploaded_work = models.BooleanField(default=True)
    email_new_messages = models.BooleanField(default=False)
    email_deadline = models.BooleanField(default=True)
    
    app_uploaded_work = models.BooleanField(default=True)
    app_new_messages = models.BooleanField(default=True)
    app_deadline = models.BooleanField(default=True)
    
    payment_option = models.CharField(max_length=20, choices=payment_choices, null=True, blank=True)

    def __str__(self) -> str:
        return (str(self.user))

class Freelancer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    email_uploaded_work = models.BooleanField(default=True)
    email_new_messages = models.BooleanField(default=True)
    email_deadline = models.BooleanField(default=True)
    
    app_uploaded_work = models.BooleanField(default=True)
    app_new_messages = models.BooleanField(default=True)
    app_deadline = models.BooleanField(default=True)
    
    def __str__(self) -> str:
        return (str(self.user))

class Profile(models.Model):
    
    user = models.OneToOneField(User,on_delete=models.CASCADE)
    first_name = models.CharField(max_length=40, null=True, blank=True)
    last_name = models.CharField(max_length=40, null=True, blank=True)
    email = models.EmailField(blank=True, null=True)  
    bio = models.TextField(max_length=240, blank=True, null=True)      
    profile_photo = models.FileField(upload_to='files/profile-photo', blank=True, null=True, max_length=255)
    
    
    def __str__(self) -> str:
        return str(self.user)

class Solved(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=80)
    amount = models.FloatField()
    category = models.CharField(max_length=20) 
    solution = models.FileField(upload_to='files/solved/', blank=True, null=True, max_length=255)

    def __str__(self) -> str:
        return str(self.title)

class Order(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, blank=True, null=True)
    freelancer = models.ForeignKey(Freelancer, on_delete=models.CASCADE, blank=True, null=True)
    title = models.CharField(max_length=80)
    category = models.CharField(max_length=20)
    deadline = models.DateTimeField()
    instructions = models.TextField(blank=True, null=True)
    status_choices = [
        ('Available', 'Available'),
        ('In Progress','In Progress'),
        ('Completed','Completed')
    ]
    subject = models.CharField(max_length=40, blank=True, null=True)
    milestones = models.IntegerField(blank=True, null=True, default=1)
    page_count = models.IntegerField(blank=True, null=True)     
    status = models.CharField(max_length=20, choices=status_choices, default='Available')
    attachment = models.FileField(upload_to='files/attachments/', blank=True, null=True, max_length=255)
    amount = models.FloatField()
    paid = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated = models.DateTimeField(auto_now=True, null=True, blank=True)

    def get_total_bids(self):
        return self.bid_set.count()
    
    def get_bidders(self):
        return self.bid_set
    
    def __str__(self) -> str:
        return str(self.title)

class Bid(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    order = models.ForeignKey(Order, on_delete=models.CASCADE, blank=True, null=True, related_name='bid_set')
    freelancer = models.ForeignKey(Freelancer, on_delete=models.CASCADE, blank=True, null=True)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, blank=True, null=True)
    amount = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)

    class Meta:
        unique_together = ('order','freelancer')

    def __str__(self) -> str:
        return str(self.order)

class Solution(models.Model):
    solution_type =[
        ('Draft', 'Draft'),
        ('Final', 'Final')
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    solution = models.FileField(upload_to='files/solution/', blank=True, null=True, max_length=255)
    _type = models.CharField(choices=solution_type, default='Final', max_length=20)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return str(self.order) + ' solution'

class Rating(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    order = models.OneToOneField(Order, on_delete=models.CASCADE)
    stars = models.FloatField(blank=True,null=True)
    message = models.CharField(max_length=150, blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True, null=True)


    def __str__(self) -> str:
        return str(self.stars) +'-'+ str(self.order)

class Chat(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    order = models.ForeignKey(Order, related_name='order', on_delete=models.CASCADE, null=True, blank=True)
    sender = models.ForeignKey(User, related_name='sender', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='receiver', on_delete=models.CASCADE)    
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return str(str(self.sender) + ' to ' +str(self.receiver))

class Transaction(models.Model):
    channel_choices = [
        ('Paypal','Paypal'),
        ('Stripe','Stripe')
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    transaction_id = models.CharField(blank=True, null=True, max_length=20)
    order = models.ForeignKey(Order, related_name='order_completed', on_delete=models.CASCADE, null=True, blank=True)    
    _from = models.ForeignKey(User,blank=True, related_name='_from', null=True, on_delete=models.CASCADE)
    _to = models.ForeignKey(User, related_name='to', blank=True, null=True, on_delete=models.CASCADE)
    amount_value = models.FloatField()   
    paypal_fee_value = models.FloatField(default=0) 
    net_amount_value = models.FloatField(blank=True, null=True) 
    currency_code = models.CharField(max_length=5, default='USD')
    channel = models.CharField(max_length=20, choices=channel_choices, default='Paypal')
    status = models.CharField(max_length=20, blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return str(self.order) +'-'+ str(self.transaction_id)
    
    
class Notification(models.Model):
    # id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.CharField(max_length=250)
    created_at = models.DateTimeField(auto_now_add=True)
    order = models.ForeignKey(Order, on_delete=models.CASCADE, null=True, blank=True)
    read_status = models.BooleanField(max_length=20,blank=True, null=True, default=False)

    def __str__(self) -> str:
        return str(self.user) + ' - notification'
    
class Subscribers(models.Model):
    reason_choices = [
        ("New Feature", "New Feature"),
        ("Emailling", "Emailling")
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(max_length=255, blank=True, null=True)
    joined_at = models.DateTimeField(auto_now_add=True, blank=True)
    reason  = models.CharField(max_length=47, choices=reason_choices, default="Emailling")
    
    def __str__(self) -> str:
        return str(self.email)
    
class SupportChat(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    topic = models.TextField()
    order = models.ForeignKey(Order, related_name='support_order', on_delete=models.CASCADE, null=True, blank=True)
    sender = models.ForeignKey(User, related_name='support_sender', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='support_receiver', on_delete=models.CASCADE) 
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self) -> str:
        return str(f"Support - FROM: {self.sender} TO: {self.receiver}")
    

