from django.shortcuts import render, redirect
from .models import User
from django.contrib import messages
import bcrypt

# Create your views here.
def index(request):
    return render(request, "index.html")

# def validate_login(request):
#     user = User.objects.get(email=request.POST['email'])  # hm...¿Es realmente una buena idea usar aquí el método get?
#     if bcrypt.checkpw(request.POST['password'].encode(), user.pw_hash.encode()):
#         print("password match")
#     else:
#         print("failed password")

def register(request):
    if request.method == 'POST':
        errors = User.objects.reg_validator(request.POST)
        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/')
        else:
            password = request.POST['password']
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()  
            print(pw_hash)   

            new_user = User.objects.create(name=request.POST['name'], alias=request.POST['alias'], email=request.POST['email'], password=pw_hash)
            print(new_user)
            request.session['user_id'] = new_user.id
            request.session['user_name'] = f"{new_user.name} {new_user.alias}"
            request.session['status'] = "registered"




        return redirect("/success") # nunca renderizar en una publicación, ¡siempre redirigir!
    return redirect("/")

def login(request):
    if request.method == 'POST':
        errors = User.objects.log_validator(request.POST)
        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/')
        else:
            user = User.objects.filter(alias=request.POST['alias'])
            if user:
                logged_user = user[0] #solo hay un usuario con ese alias, por lo que se usa [0]
                if bcrypt.checkpw(request.POST['password'].encode(), logged_user.password.encode()):
                    request.session['user_id'] = logged_user.id
                    request.session['user_name'] = f"{logged_user.name} {logged_user.alias}"
                    request.session['status'] = "Logged in"
            
                    return redirect('/success')
                else: 
                    messages.error(request, "password invalid")
        return redirect("/")

def success(request):

    return render (request, "success.html")