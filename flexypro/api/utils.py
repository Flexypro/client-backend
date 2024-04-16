from django.conf import settings
from django.core.mail import EmailMultiAlternatives

import requests
import random,  string
from decouple import config as env
from .models import Order

class Util:

    # def read_template(filename):
    #     template_dir = os.path.join(os.path.dirname(__file__), 'email_templates')
    #     template_path = os.path.join(template_dir, filename)
    #     with open(template_path, 'r') as template_file:
    #         return template_file.read()
    
    @staticmethod
    def generate_order_code(length=8) -> str:
        while True:
            numerics = ''.join(random.choices(string.digits,k=length//2))
            alphabets = ''.join(random.choices(string.ascii_uppercase,k=length//2))
            
            unique_code = numerics +'-'+ alphabets
            
            if not Order.objects.filter(unique_code=unique_code).exists():
                break
                
        return str(unique_code)

    @staticmethod
    def get_location(user=False):
        res = requests.get("http://ip-api.com/json/?fields=61439")
        
        try:
            if res.status_code == 200:
                data = res.json()
                country = data['country']
                countryCode = data['countryCode']
                timezone = data['timezone']
                ip = data['query']
                
                if user:                
                    return {
                        'countryCode':countryCode,
                        'country':country,
                        'timezone':timezone,
                        'ip':ip
                    }
                else:
                    return {
                        'countryCode':countryCode,
                        'country':country,
                        'timezone':timezone,
                    }
                
            else:
                print("Request failed")
                return {}
        except Exception as e:
            print(f'Error obtaining IP, {e}')
            return {}

    @staticmethod
    def send_email(data, *args):
        
        from_email = None        
        
        if args:
            _from = str(args[0]).lower()
                    
            if _from == 'support':
                from_email = env('SUPPORT_FROM_EMAIL')
            elif _from == 'info':
                from_email = env('INFO_FROM_EMAIL')
            else:
                from_email = None
            
        # email = EmailMessage(
        #     subject = data['email_subject'],
        #     body = data['email_body'],
        #     to = [data['email_to']],
        #     from_email=None,            
        # )
        email = EmailMultiAlternatives(
            subject = data['email_subject'],
            body = data['email_body'],
            to = [data['email_to']],
            from_email=from_email
            # from_email='security@gigitise.com',  
        )
        
        email.content_subtype = "html"  # Main content is now text/html
        try:
            email.send()
        except Exception as e:
            print(e)
            print("Error sending email")
            pass
            return

    @staticmethod
    def generate_otp(self): 
        return self.now()
    
    @staticmethod
    def verify_otp(self, otp, otp_object):
        if otp_object:
            expired = False
            print("Used: ", otp_object.used)
            if otp == otp_object.otp and otp_object.used==False and not expired:
                return True
            else: return False
        else: return False
        
def get_token():
    client_id = "AXTNDnVO8iNy8GgqF6gRHGHLptXoDhMIWAyCQZK-jytA5gmPBGBlk_cUsA9n38Go06bvwkKGCGI7gKpe"
    client_secret = "EHkMI6B3f1I7F3rifJtfNsVtU-ZeDub90Stj2T0srPDSuRC2Ybcr5mGNbvWAY2RAA7xyk3SxNSS3xKRr"
    # Get access token
    auth_url = "https://api-m.sandbox.paypal.com/v1/oauth2/token"
    auth_data = {
        'grant_type': 'client_credentials',
    }
    auth_headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    auth = (client_id, client_secret)

    response = requests.post(auth_url, data=auth_data, headers=auth_headers, auth=auth)
    access_token = response.json().get('access_token') 
    return access_token

def create_order(amount, access_token):
    order_url = "https://api-m.sandbox.paypal.com/v2/checkout/orders"
    order_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}',
    }

    order_data = {
        "intent":"CAPTURE",
        "purchase_units": [
            {
                "amount": {
                    "currency_code": "USD",
                    "value": amount,
                },
            }
        ],
    }

    response = requests.post(order_url, json=order_data, headers=order_headers,)
    return response.json()

def capture_payment(id, access_token):
    print("Capturing payment...")
    order_url = f"https://api-m.sandbox.paypal.com/v2/checkout/orders/{id}/capture"
    order_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}',
    }
    response = requests.post(order_url, headers=order_headers)
    response = response.json()
    paypal_id = response['id']
    status_value = response['status']
    amount_value = response['purchase_units'][0]['payments']['captures'][0]['amount']['value']
    paypal_fee_value = response['purchase_units'][0]['payments']['captures'][0]['seller_receivable_breakdown']['paypal_fee']['value']
    net_amount_value = response['purchase_units'][0]['payments']['captures'][0]['seller_receivable_breakdown']['net_amount']['value']
    currency_code = response['purchase_units'][0]['payments']['captures'][0]['amount']['currency_code']

    return paypal_id, amount_value, paypal_fee_value, net_amount_value, currency_code, status_value