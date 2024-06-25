from django.urls import path
from . import views

from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.home,name='blog-home'),
    path('about/', views.about,name='blog-about'),
    path('upload/', views.upload, name='blog-upload'),  # Added URL pattern for upload
    path('success/', views.success, name='blog-success'),
    path('login/', views.login_view, name='blog-login'),
    path('users/', views.user_list, name='blog-list'), 
    path('upload-images/', views.upload_images_view, name='upload-images'),
    path('delete/<int:user_id>/', views.delete_user, name='delete_user'),
    path('edit/<int:user_id>/', views.edit_user, name='edit_user'),
    path('update/<int:id>/', views.update, name='update_user'),
    path('start-iteration/', views.start_iteration, name='start-iteration'),
    path('check-progress/', views.check_progress, name='check-progress'),
    path('generated_images/', views.generated_images, name='generated_images'),
    path('download/<int:user_id>/<str:image_name>/', views.download_image, name='download_image')
  
    
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)