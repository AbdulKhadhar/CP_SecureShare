# secureshare/urls.py
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from core import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('upload/', views.upload_file, name='upload_file'),
    path('files/', views.my_files, name='my_files'),
    path('files/<uuid:file_id>/delete/', views.delete_file, name='delete_file'),
    path('files/<uuid:file_id>/create-link/', views.create_link, name='create_link'),
    path('links/', views.my_links, name='my_links'),
    path('links/<uuid:link_id>/', views.link_details, name='link_details'),
    path('links/<uuid:link_id>/deactivate/', views.deactivate_link, name='deactivate_link'),
    path('download/<str:token>/', views.download_file, name='download_file'),
    path('activity/', views.activity_logs, name='activity_logs'),
    path('notifications/', views.notifications, name='notifications'),
    path('analytics/', views.analytics, name='analytics'),
    path('admin-panel/', views.admin_dashboard, name='admin_dashboard'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)