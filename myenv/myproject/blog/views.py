from django.shortcuts import render,redirect
from django.http import HttpResponse
# Create your views here.
from .forms import UserForm
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login
from django.contrib import messages
from .models import User
from django.contrib.auth.hashers import check_password
from .forms import ImageUploadForm
from .models import UserImages
import os
import subprocess
from django.conf import settings
from django.shortcuts import get_object_or_404
from .models import Department, DepartmentWiseUser
from django.contrib.auth.hashers import make_password
import bcrypt
from django.contrib.auth.hashers import check_password
import threading
import time

from django.http import JsonResponse
import base64
from django.conf import settings
from cryptography.fernet import Fernet
posts=[
    {
        'author':'CoreyMS',
        'title':'Blog Post 1',
        'content':'First post content',
        'date_posted':'August 27,2018'
    },
     {
        'author':'Jane Doe',
        'title':'Blog Post 2',
        'content':'Second post content',
        'date_posted':'August 28,2018'
    },
]

# Put this somewhere safe!
key = b'YLFS2Wd0ATbiTkQKBYv41GFROvI7B8ljWcwwO4kkATM='
#key = "KFlopm8989DSklo"
cipher_suite = Fernet(key)


# Global variable to track progress
progress = 0

def start_iteration(request):
    print('in start iteration')
    global progress
    progress = 0  # Reset progress

    # Run the iteration in a separate thread
    threading.Thread(target=run_iteration).start()
    print(progress)
    return JsonResponse({'status': 'Iteration started'})

def run_iteration():
    global progress
    print('in run iteration')
    for i in range(500):
        print(i)
        time.sleep(0.1)  # Simulate work being done
        progress = round((i + 1) * 100 / 500) 
        #progress = (i + 1) * 100 / 500
        print(progress)

def check_progress(request):
    global progress
    print('in check progress')
    print(progress)
    return JsonResponse({'progress': progress})

def home(request):
#receive request
    #return HttpResponse('<h1>Welcome Home</h1>')
    user_email = request.session.get('user_email')
    user_name = request.session.get('user_name')

    # Pass user's email and name to the template
    context = {'user_email': user_email, 'user_name': user_name}
    return render(request, 'blog/home.html', context)




def about(request):
    return render(request,'blog/about.html')
    #return HttpResponse('<h1>Blog About</h1>')
    
#def upload(request):
    #return render(request, 'blog/upload.html')


def upload6(request):
    if request.method == 'POST':
        form = UserForm(request.POST)
        propassword = request.POST.get('password')
       # hashed_password = make_password(propassword)
        #print("Hashed Password:", hashed_password) 
        key = Fernet.generate_key()
       # encoded_key = base64.urlsafe_b64encode(key)
        f=Fernet(key)
        token = f.encrypt(propassword.encode('utf-8'))
        print(token)
        #print(encoded_key)
        #print(key)
        #cipher_suite = Fernet(key)
        
        if form.is_valid():
            user = form.save(commit=False)  # Create user instance but don't save to database yet
            #password_bytes=propassword.encode() 
            #print(password_bytes)
            
            #encrypted_password = cipher_suite.encrypt(password_bytes)
           # encoded_encrypted_password = base64.urlsafe_b64encode(encrypted_password).decode('utf-8')
            
            #encrypted_password = cipher_suite.encrypt(password_bytes)
            #print(f"Encrypted password: {encrypted_password}")
         #   user.password = hashed_password  # Assign the hashed password
            user.password = token
            user.save()  # Save the user instance with the hashed password
            
           # user = form.save()  # Save the user instance
            
            department_ids = request.POST.getlist('department')  # Get list of selected department IDs
            
            # Loop through each selected department and create a DepartmentWiseUser instance
            for department_id in department_ids:
                department = Department.objects.get(departmentid=department_id)  # Fetch the department
                DepartmentWiseUser.objects.create(user=user, department=department)  # Create and save the relationship

            return render(request, 'blog/success.html')
    else:
        form = UserForm()
    
    departments = Department.objects.all()  # Fetch all departments from the Department table
    return render(request, 'blog/upload.html', {'form': form, 'departments': departments})

def upload(request):
    if request.method == 'POST':
        form = UserForm(request.POST)
        propassword = request.POST.get('password')
        #p=propassword.encode()
       
        # Encrypt the password using the global Fernet cipher
       # ciphertext = cipher_suite.encrypt(p)
       # print(ciphertext)
        ciphertext=encrypt_password(propassword,key)
        print(ciphertext)
        if form.is_valid():
            user = form.save(commit=False)  # Create user instance but don't save to database yet
            user.password =ciphertext  # Assign the encrypted password
            user.save()  # Save the user instance
            
            department_ids = request.POST.getlist('department')  # Get list of selected department IDs
            for department_id in department_ids:
                department = Department.objects.get(departmentid=department_id)  # Fetch the department
                DepartmentWiseUser.objects.create(user=user, department=department)  # Create and save the relationship

            return render(request, 'blog/login.html')
    else:
        form = UserForm()
    
    departments = Department.objects.all()  # Fetch all departments from the Department table
    return render(request, 'blog/upload.html', {'form': form, 'departments': departments})

def success(request):
    return render(request, 'blog/success.html')

def encrypt_password(password, key):
    fernet = Fernet(key)

    encrypted_password = fernet.encrypt(password.encode())
    return base64.urlsafe_b64encode(encrypted_password).decode()

def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)

    encrypted_password_bytes = base64.urlsafe_b64decode(encrypted_password.encode())
    decrypted_password = fernet.decrypt(encrypted_password_bytes).decode()
    return decrypted_password



def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        print(email)
        print(password)
        
        try:
            # Get the user by email
            user = User.objects.get(email=email)
            print('User found:', user.email)

            decryptpassword=decrypt_password(user.password,key)
           
            # Check if the provided password matches the decrypted password
            if password == decryptpassword:
                # Print login success message
                print('login successfully')
                request.session['user_email'] = user.email
                request.session['user_name'] = user.firstname
                
                # Redirect to the home page or any other desired page
                return redirect('blog-home')  # Assuming 'blog-home' is the URL name for the home page
            else:
                # Incorrect password
                messages.error(request, 'Incorrect password.')
        except User.DoesNotExist:
            # User with this email does not exist
            messages.error(request, 'User with this email does not exist.')
        except Exception as e:
            # Catch any other exceptions and log them
            print(f'Error during login: {e}')
            messages.error(request, 'An error occurred during login. Please try again.')

    return render(request, 'blog/login.html')

def user_list(request):
    users = User.objects.all()  # Fetch all users from the database
    department_wise_users = DepartmentWiseUser.objects.all()  # Fetch all records from DepartmentWiseUser
    return render(request, 'blog/list.html', {'users': users, 'department_wise_users': department_wise_users})



def run_command(user_id, image_path):

    print('in command prompt function ', user_id)
    project_name = f'user{user_id}'
    print(image_path)
    print('innnn')
    command = [
        'autotrain', 'dreambooth', '--train',
        '--model', 'stabilityai/stable-diffusion-xl-base-1.0',
        '--project-name', project_name,
        '--image-path', image_path,
        '--prompt', 'A photo of Ayush wearing casual clothes and smiling.',
        '--resolution', '1024',
        '--batch-size', '1',
        '--num-steps', '500',
        '--gradient-accumulation', '4',
        '--lr', '1e-4',
        '--mixed-precision', 'fp16'
    ]
    
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        # Handle errors in command execution here
        print(f"An error occurred: {e}")


def upload_images_view(request):
    print('hii1st')
    if request.method == 'POST':
        print('2nd')
        form = ImageUploadForm(request.POST, request.FILES)
        user_email = request.session.get('user_email')
        user_name = request.session.get('user_name')
        user_id = request.session.get('user_id')   # Fallback to user_id 4 for now

        # Fetch user ID from the User table based on user_email
        user = get_object_or_404(User, email=user_email)
        user_id = user.id
        
        print('helloooooo', user_id)
        print(user_email)
        print(user_name)
        if form.is_valid():
            print('3rd')
            
            # Ensure the media directory exists
            media_folder = settings.MEDIA_ROOT
            os.makedirs(media_folder, exist_ok=True)

            # Create user-specific folder within the media folder if it doesn't exist
            user_folder = os.path.join(media_folder, str(user_id))
            os.makedirs(user_folder, exist_ok=True)

            for file in request.FILES.getlist('image_url'):
                file_path = os.path.join(user_folder, file.name)
                with open(file_path, 'wb+') as destination:
                    for chunk in file.chunks():
                        destination.write(chunk)
                
                # Save to the database
                user = User.objects.get(pk=user_id)
                UserImages.objects.create(user=user, image_url=os.path.join(str(user_id), file.name))
                
            # After saving the images, call run_command()
            user_directory = f'media/{user_id}/'  # assuming user_id is correct here
            print(user_directory)
            print(user_id)
            print('before runcommand')
            
            #run_command(user_id, user_directory)

            print('after runcommand')
            
            context = {'user_email': user_email, 'user_name': user_name, 'form': form}
            return render(request, 'blog/home.html', context)
    else:
        form = ImageUploadForm()
        user_email = request.session.get('user_email')
        user_name = request.session.get('user_name')
        context = {'user_email': user_email, 'user_name': user_name, 'form': form}
        return render(request, 'blog/home.html', context)


def upload_images_view2(request):
    print('hii1st')
    if request.method == 'POST':
        print('2nd')
        form = ImageUploadForm(request.POST, request.FILES)
        user_email = request.session.get('user_email')
        user_name = request.session.get('user_name')
        user_id = request.session.get('user_id')   # Fallback to user_id 4 for now

        # Fetch user ID from the User table based on user_email
        user = get_object_or_404(User, email=user_email)
        user_id = user.id
        
        print('helloooooo', user_id)
        print(user_email)
        print(user_name)
        if form.is_valid():
            print('3rd')
            
            # Ensure the images directory exists
            images_folder = os.path.join(settings.MEDIA_ROOT, 'images')
            os.makedirs(images_folder, exist_ok=True)

            # Create user-specific folder within the images folder if it doesn't exist
            user_folder = os.path.join(images_folder, str(user_id))
            os.makedirs(user_folder, exist_ok=True)

            for file in request.FILES.getlist('image_url'):
                file_path = os.path.join(user_folder, file.name)
                with open(file_path, 'wb+') as destination:
                    for chunk in file.chunks():
                        destination.write(chunk)
                
                # Save to the database
                user = User.objects.get(pk=user_id)
                
                UserImages.objects.create(user=user, image_url=os.path.join('images', str(user_id), file.name))
                
            # After saving the images, call run_command()
            user_directory = f'/media/images/{user_id}/'  # assuming user_id is correct here
            print(user_directory)
            print(user_id)
            print('before runcommand')
            
            run_command(user_id, user_directory)

            print('after runcommand')
            
            context = {'user_email': user_email, 'user_name': user_name, 'form': form}
            return render(request, 'blog/home.html', context)
    else:
        form = ImageUploadForm()
        user_email = request.session.get('user_email')
        user_name = request.session.get('user_name')
        context = {'user_email': user_email, 'user_name': user_name, 'form': form}
        return render(request, 'blog/home.html', context)

def upload_images_view3(request):
    print('hii1st')
    if request.method == 'POST':
        print('2nd')
        form = ImageUploadForm(request.POST, request.FILES)
        user_email = request.session.get('user_email')
        user_name = request.session.get('user_name')
        user_id = request.session.get('user_id')   # Fallback to user_id 4 for now

          # Fetch user ID from the User table based on user_email
        user = get_object_or_404(User, email=user_email)
        user_id = user.id
        
        print('helloooooo', user_id)
        print(user_email)
        print(user_name)
        if form.is_valid():
            print('3rd')
            
            # Ensure the images directory exists
            images_folder = os.path.join(settings.MEDIA_ROOT, 'images')
            os.makedirs(images_folder, exist_ok=True)

            # Create user-specific folder within the images folder if it doesn't exist
            user_folder = os.path.join(images_folder, str(user_id))
            os.makedirs(user_folder, exist_ok=True)

            for file in request.FILES.getlist('image_url'):
                file_path = os.path.join(user_folder, file.name)
                with open(file_path, 'wb+') as destination:
                    for chunk in file.chunks():
                        destination.write(chunk)
                
                # Save to the database
                user = User.objects.get(pk=user_id)
                
                UserImages.objects.create(user=user, image_url=os.path.join('images', str(user_id), file.name))
                user_directory = f'/media/images/{request.user.id}/'
                #run_command(request.user.id, user_directory)

            context = {'user_email': user_email, 'user_name': user_name, 'form': form}
            return render(request, 'blog/home.html', context)
    else:
        form = ImageUploadForm()
        user_email = request.session.get('user_email')
        user_name = request.session.get('user_name')
        context = {'user_email': user_email, 'user_name': user_name, 'form': form}
        return render(request, 'blog/home.html', context)   

def upload_images_view1(request):
    print('hii1st')
    if request.method == 'POST':
        print('2nd')
        form = ImageUploadForm(request.POST, request.FILES)
        user_email = request.session.get('user_email')
        user_name = request.session.get('user_name')
        user_id = request.session.get('user_id')   # Fallback to user_id 4 for now

        # Fetch user ID from the User table based on user_email
        user = get_object_or_404(User, email=user_email)
        user_id = user.id
        
        print('helloooooo', user_id)
        print(user_email)
        print(user_name)
        if form.is_valid():
            print('3rd')
            
            # Ensure the images directory exists
            images_folder = os.path.join(settings.MEDIA_ROOT, 'images')
            os.makedirs(images_folder, exist_ok=True)

            # Create user-specific folder within the images folder if it doesn't exist
            user_folder = os.path.join(images_folder, str(user_id))
            os.makedirs(user_folder, exist_ok=True)

            for file in request.FILES.getlist('image_url'):
                file_path = os.path.join(user_folder, file.name)
                with open(file_path, 'wb+') as destination:
                    for chunk in file.chunks():
                        destination.write(chunk)
                
                # Save to the database
                user = User.objects.get(pk=user_id)
                
                UserImages.objects.create(user=user, image_url=os.path.join('images', str(user_id), file.name))
                #user_directory = f'/media/images/{request.user.id}/'
                #try:
                    #run_command(request.user.id, user_directory)
                #except Exception as e:
                   # print(f"Error occurred while running command: {e}")

            context = {'user_email': user_email, 'user_name': user_name, 'form': form}
            return render(request, 'blog/home.html', context)
    else:
        form = ImageUploadForm()
        user_email = request.session.get('user_email')
        user_name = request.session.get('user_name')
        context = {'user_email': user_email, 'user_name': user_name, 'form': form}
        return render(request, 'blog/home.html', context)


def delete_user(request, user_id):
    if request.method == 'POST':
        # Fetch the user
        user = get_object_or_404(User, id=user_id)
        
        # Fetch related DepartmentWiseUser records based on user_id
        department_wise_users = DepartmentWiseUser.objects.filter(user_id=user_id)
        
        # Delete related DepartmentWiseUser records
        department_wise_users.delete()
        
        # Delete the user
        user.delete()
        
        return redirect('blog-list')
    
    # If it's not a POST request, return a method not allowed response
    return HttpResponse(status=405)

def delete_user1(request, user_id):
    print('in delete blok')
    if request.method == 'GET':
        # Fetch the user
        user = get_object_or_404(User, id=user_id)
        
        # Fetch related DepartmentWiseUser records based on user_id
        department_wise_users = DepartmentWiseUser.objects.filter(user_id=user_id)
        
        # Delete related DepartmentWiseUser records
        department_wise_users.delete()
        
        # Delete the user
        user.delete()
        
        return redirect('blog-list')
    return HttpResponse(status=405)

  
def edit_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    departments = Department.objects.all()
    selected_department_ids = list(user.departmentwiseuser_set.values_list('department_id', flat=True))
   # return render(request, 'blog/edit.html', {'user': user, 'departments': departments})
      
    return render(request, 'blog/edit.html', {'user': user, 'departments': departments, 'selected_department_ids': selected_department_ids})


def update(request, id):
    user = User.objects.get(id=id)
    form = UserForm(request.POST, instance=user)
    if form.is_valid():
        
        form.save()
        
        # Get the selected department IDs from the form
        selected_department_ids = request.POST.getlist('department')
        
        # Update DepartmentWiseUser records for the user
        DepartmentWiseUser.objects.filter(user=user).delete()  # Remove existing records
        for department_id in selected_department_ids:
            department_user = DepartmentWiseUser(user=user, department_id=department_id)
            department_user.save()
        
        return redirect("/users")
    
    departments = Department.objects.all()
    return render(request, 'blog/edit.html', {'user': user, 'departments': departments})

