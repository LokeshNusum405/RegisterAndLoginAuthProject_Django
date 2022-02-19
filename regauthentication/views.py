
from django.contrib.sites.shortcuts import get_current_site
from tokenize import generate_tokens
from RegistrationProject import settings
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import send_mail,EmailMessage
from django.contrib.auth import authenticate,login,logout
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes,force_str
from . tokens import generate_token
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode

# Create your views here.

def home(request):
    return render(request,'regauthentication/index.html')


def signup(request):
    if request.method=="POST":
        # username = request.POST.get('username')
        username = request.POST['username']
        fname = request.POST['firstname']
        lname = request.POST['lastname']
        email = request.POST['email']
        password = request.POST['password']
        cpassword = request.POST['cpassword']

        if User.objects.filter(username=username):
            messages.error(request,'Username already exists')
            return redirect('home')
        if User.objects.filter(email=email):
            messages.error(request,'Email already exists')
            return redirect('home')
        if password!=cpassword:
            messages.error(request,'Password does not match')
            return redirect('home')
        if len(username)>10:
            messages.error(request,'Username too long Must be less than 10 characters')
            return redirect('home')
        if not username.isalnum():
            messages.error(request,'Username should only contain alphanumeric characters')
            return redirect('home')

        myuser = User.objects.create_user(username,email,password)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False
        myuser.save()

        
        #Welcome Email
        subject = "Welcome to the Lokesh Registration Authentication Django Project"
        message = "Hello" + myuser.username + "\nWelcome to the Lokesh Registration Authentication Django Project \n Thanks for registering with us \n We have sent you a confirmation email please confirm your email\n\n Regards \n Lokesh "
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject,message,from_email,to_list,fail_silently=True)

        #EmailAddress Confirmation
        current_site=get_current_site(request)
        email_subject = "Confirm Email Address @ Lokesh Registration Authentication Django Project"
        message2 = render_to_string('regauthentication/email_confirmation_message.html',{
            'name':myuser.username,
            'domain':current_site.domain,
            'uid':urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token':generate_token.make_token(myuser),
        })
        email = EmailMessage(email_subject,message2,from_email,to_list)
        email.send()
        messages.success(request,'Your Account has been created successfully.we have sent you a Confirmation email please confirm the email to activate your account')

        return redirect('signin')
    return render(request,'regauthentication/signup.html')

def signin(request):
    if request.method=="POST":
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username=username,password=password)

        if user is not None:
            login(request,user)
            uname=user.username
            return render(request,'regauthentication/index.html',{'uname':uname})
        else:
            messages.error(request,'Invalid Credentials')
            return redirect('home')


    return render(request,'regauthentication/signin.html')

def signout(request):
    
    logout(request)
    messages.success(request,"You have been logged out successfully")
    return redirect('home')

def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except(TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None
    
    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        
        myuser.save()
        login(request,myuser)
        return redirect('home')
    else:
        messages.error(request,'Activation link is invalid!')
        return redirect('home')

