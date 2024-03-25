from django.contrib import admin
from .models import (
    Client, 
    Order, 
    Notification, 
    Rating, Solved,
    Chat, 
    Transaction, 
    Solution,
    Profile,
    Freelancer,
    User,
    OTP,
    Bid,
    Subscribers,
    SupportChat
)

# Register your models here.
admin.site.register(User)
admin.site.register(Client)
admin.site.register(Order)
admin.site.register(OTP)
admin.site.register(Notification)
admin.site.register(Rating)
admin.site.register(Solved)
admin.site.register(Chat)
admin.site.register(Transaction)
admin.site.register(Solution)
admin.site.register(Profile)
admin.site.register(Freelancer)
admin.site.register(Bid)
admin.site.register(Subscribers)
admin.site.register(SupportChat)
# models = [Client, Order, Notification, Rating, Solved, Chat]
# for model in models:
#     admin.site.register(model)