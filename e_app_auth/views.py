from django.shortcuts import render,redirect
from django.contrib.auth.models import User
from django.views.generic import View
from django.contrib import auth,messages
# To activate the user account
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.urls import NoReverseMatch,reverse
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes,force_str,DjangoUnicodeDecodeError
#Getting tokens from utils.py 
from .utils import TokenGenerator,generate_token
#Reset Password Generator
from django.contrib.auth.tokens import PasswordResetTokenGenerator
# Emails
from django.core.mail import  send_mail ,EmailMultiAlternatives,EmailMessage
from django.core.mail import BadHeaderError,send_mail
from django.core import mail
from django.conf import settings 
#Threading
import threading

class EmailThread(threading.Thread):
    def __init__(self, email_message):
        self.email_message = email_message
        threading.Thread.__init__(self)
    def run(self):
        self.email_message.send()



# Create your views here.
def signup(request):
    if request.method =='POST':
        username=request.POST['name']
        email=request.POST['email']
        password=request.POST['password']
        repeat_password=request.POST['repeat_password']
        if password!=repeat_password:
            messages.warning(request,"Password doesnt match")
            return render(request,'auth/signup.html')
            
        try:
            if User.objects.filter(username=email).exists():
                messages.warning(request,"Email is Taken")
                return render(request,'auth/signup.html')
        except Exception as itendifier:
                pass
        user=User.objects.create_user(username=email, email=email, password=password)
        user.is_active=False
        user.save()
        current_site=get_current_site(request)
        email_subject="Activate your account"
        message=render_to_string('auth/activate.html',{
            'user':'user',
            'domain':'127.0.0.1:8000',
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
            'token':generate_token.make_token(user)
        })
        email_message=EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email],)
        EmailThread(email_message).start()
        messages.info(request,"Activate your account by clicking link on your email")
        return redirect('login') 
    else:    
        return render(request,'auth/signup.html')
    

class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=uid)
        except Exception as identifier:
            user=None
        if user is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            messages.info(request,"Account Activated Successfully")
            return redirect('login')
        return render(request,'activatefail.html')
def login(request):
    if request.method=='POST':
        username=request.POST['name']
        password=request.POST['password']
        user=auth.authenticate(request,username=username,password=password)
        if user is not None:
            auth.login(request,user)
            return redirect('home')
        else:
            messages.warning(request,"Invalid Username or password")
            return render(request,"auth/login.html")
    else:
        return render(request,'auth/login.html')
    
def logout(request):
    auth.logout(request)
    messages.success(request,"Logout success")
    return redirect('login')
    


class RequestResetEmailView(View):
    def get(self, request):
        return render(request, 'auth/request-reset-email.html')
    
    def post(self, request):
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()

        if user:
            email_subject = '[Reset Your Password]'
            message = render_to_string('auth/reset-user-password.html', {
                'domain': '127.0.0.1:8000',
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': PasswordResetTokenGenerator().make_token(user)
            })

            email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
            email_message.send()

            messages.info(request, "We have sent you an email with instructions on how to reset the password.")
        else:
            messages.error(request, "No user found with this email address.")

        return render(request, 'auth/request-reset-email.html')
    

class SetNewPasswordView(View):
    def get(self,request,uidb64,token):
        context = {
            'uidb64':uidb64,
            'token':token
        }
        try:
            user_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)

            if  not PasswordResetTokenGenerator().check_token(user,token):
                messages.warning(request,"Password Reset Link is Invalid")
                return render(request,'request-reset-email.html')

        except DjangoUnicodeDecodeError as identifier:
            pass

        return render(request,'set-new-password.html',context)

    def post(self,request,uidb64,token):
        context={
            'uidb64':uidb64,
            'token':token
        }
        password=request.POST['pass1']
        confirm_password=request.POST['pass2']
        if password!=confirm_password:
            messages.warning(request,"Password is Not Matching")
            return render(request,'auth/set-new-password.html',context)
        
        try:
            user_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request,"Password Reset Success Please Login with NewPassword")
            return redirect('/auth/login/')

        except DjangoUnicodeDecodeError as identifier:
            messages.error(request,"Something Went Wrong")
            return render(request,'set-new-password.html',context)

        return render(request,'auth/set-new-password.html',context)
                       