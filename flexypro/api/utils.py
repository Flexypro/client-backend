import json
import time
from django.conf import settings
from django.core.mail import EmailMessage
import pyotp
from rest_framework.response import Response
from rest_framework import status
import requests

class Util:

    # topt = pyotp.TOTP(settings.OTP_KEY)
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
    def send_email(data, ):
        email = EmailMessage(
            subject = data['email_subject'],
            body = data['email_body'],
            to = [data['email_to']],
            from_email=None,            
        )

        email.send()

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