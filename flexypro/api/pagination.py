from rest_framework.pagination import PageNumberPagination

class OrdersPagination(PageNumberPagination):
    page_size = 5

class NotificationsPagination(PageNumberPagination):
    page_size = 5
    
class TransactionsPagination(PageNumberPagination):
    page_size = 5

class ChatsPagination(PageNumberPagination):
    page_size = 5

class SolutionPagination(PageNumberPagination):
    page_size = 5

class BiddersPagination(PageNumberPagination):
    page_size = 5