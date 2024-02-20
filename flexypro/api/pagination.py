from rest_framework.pagination import PageNumberPagination

class OrdersPagination(PageNumberPagination):
    page_size = 1

class NotificationsPagination(PageNumberPagination):
    page_size = 1
    
class TransactionsPagination(PageNumberPagination):
    page_size = 1

class ChatsPagination(PageNumberPagination):
    page_size = 20

class BiddersPagination(PageNumberPagination):
    page_size = 1