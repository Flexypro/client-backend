# permissions.py
from rest_framework import permissions

class IsOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        # Check if the request user is the owner of the order
        print(obj.user, request.user)
        return obj.user == request.client if obj else False