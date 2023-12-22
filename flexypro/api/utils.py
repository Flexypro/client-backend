import time
from django.conf import settings
from django.core.mail import EmailMessage
import pyotp
from rest_framework.response import Response
from rest_framework import status
class Util:

    # topt = pyotp.TOTP(settings.OTP_KEY)

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
        
        
        