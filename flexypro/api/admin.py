from django.contrib import admin
from .models import Client, Order, Notification, Rating, Solved, Chat

# Register your models here.
admin.site.register(Client)
admin.site.register(Order)
# admin.site.register(Chat)
admin.site.register(Notification)
admin.site.register(Rating)
admin.site.register(Solved)
admin.site.register(Chat)

# models = [Client, Order, Notification, Rating, Solved, Chat]
# for model in models:
#     admin.site.register(model)