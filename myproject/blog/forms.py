from django import forms
from .models import User

from .models import UserImages,DepartmentWiseUser
class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['firstname','lastname', 'email', 'password', 'address', 'gender', 'mobile', 'department']
        widgets = {
            'password': forms.PasswordInput(),
        }
        
        
class ImageUploadForm(forms.ModelForm):
    class Meta:
        model = UserImages
        fields = ['image_url']
    
class DepartmentWiseUserForm(forms.ModelForm):
    class Meta:
        model = DepartmentWiseUser
        fields = ['user', 'department']