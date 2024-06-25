from django.db import models

class User(models.Model):
    id = models.AutoField(primary_key=True)
    firstname  = models.CharField(max_length=100, default='.')
    lastname = models.CharField(max_length=100, default='.')
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=500)
    address = models.CharField(max_length=255, default='Default Address')
    gender = models.CharField(max_length=10, default='Other')
    mobile = models.CharField(max_length=15, default='0000000000')
    
    department = models.ForeignKey('Department', on_delete=models.SET_NULL, null=True)
    
    def __str__(self):
        return self.email

class UserImages(models.Model):
    imgid = models.AutoField(primary_key=True)
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    image_url = models.ImageField(upload_to='user_images/')

    def __str__(self):
        return f"Image {self.imgid} for {self.user.email}"
    
    
class Department(models.Model):
    departmentid = models.AutoField(primary_key=True)
    departmentname = models.CharField(max_length=100)

    def __str__(self):
        return self.departmentname
    
    
class DepartmentWiseUser(models.Model):
    depuserid = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    department = models.ForeignKey(Department, on_delete=models.CASCADE)