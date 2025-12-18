from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.db.models import Sum, Count
from django.core.paginator import Paginator
from datetime import timedelta
from .models import *
from .encryption import FileEncryption
from .forms import *
from django.conf import settings
import os
import hashlib
import uuid

def home(request):
    return render(request, 'home.html')

def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            UserProfile.objects.create(user=user)
            login(request, user)
            messages.success(request, 'Account created successfully!')
            return redirect('dashboard')
    else:
        form = UserCreationForm()
    return render(request, 'register.html', {'form': form})

def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            ActivityLog.objects.create(
                user=user,
                activity_type='login',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            messages.success(request, f'Welcome back, {user.username}!')
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid credentials')
    return render(request, 'login.html')

@login_required
def user_logout(request):
    ActivityLog.objects.create(
        user=request.user,
        activity_type='logout',
        ip_address=get_client_ip(request)
    )
    logout(request)
    return redirect('home')

@login_required
def dashboard(request):
    profile = request.user.userprofile
    
    total_files = EncryptedFile.objects.filter(owner=request.user, is_active=True).count()
    total_links = ShareableLink.objects.filter(file__owner=request.user, is_active=True).count()
    total_downloads = ActivityLog.objects.filter(user=request.user, activity_type='download').count()
    
    recent_files = EncryptedFile.objects.filter(owner=request.user, is_active=True).order_by('-uploaded_at')[:5]
    recent_activities = ActivityLog.objects.filter(user=request.user)[:10]
    unread_notifications = Notification.objects.filter(user=request.user, is_read=False).count()
    
    context = {
        'total_files': total_files,
        'total_links': total_links,
        'total_downloads': total_downloads,
        'recent_files': recent_files,
        'recent_activities': recent_activities,
        'storage_used': profile.storage_used,
        'storage_limit': profile.storage_limit,
        'storage_percentage': (profile.storage_used / profile.storage_limit * 100) if profile.storage_limit > 0 else 0,
        'unread_notifications': unread_notifications,
    }
    return render(request, 'dashboard.html', context)

@login_required
def upload_file(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            
            profile = request.user.userprofile
            if profile.storage_used + uploaded_file.size > profile.storage_limit:
                messages.error(request, 'Storage limit exceeded!')
                return redirect('upload_file')
            
            file_data = uploaded_file.read()
            
            encryptor = FileEncryption(settings.ENCRYPTION_KEY)
            encrypted_data, iv = encryptor.encrypt_file(file_data)
            file_hash = FileEncryption.compute_hash(file_data)
            
            encrypted_filename = f"{uuid.uuid4().hex}_{uploaded_file.name}"
            file_path = os.path.join(settings.MEDIA_ROOT, 'encrypted', encrypted_filename)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            encrypted_file = EncryptedFile.objects.create(
                owner=request.user,
                original_filename=uploaded_file.name,
                encrypted_filename=encrypted_filename,
                file_size=uploaded_file.size,
                file_hash=file_hash,
                encryption_iv=iv
            )
            
            profile.storage_used += uploaded_file.size
            profile.save()
            
            ActivityLog.objects.create(
                user=request.user,
                activity_type='upload',
                file=encrypted_file,
                ip_address=get_client_ip(request),
                details=f"Uploaded {uploaded_file.name}"
            )
            
            messages.success(request, 'File uploaded and encrypted successfully!')
            return redirect('create_link', file_id=encrypted_file.id)
    else:
        form = FileUploadForm()
    return render(request, 'upload.html', {'form': form})

@login_required
def my_files(request):
    files = EncryptedFile.objects.filter(owner=request.user, is_active=True).order_by('-uploaded_at')
    paginator = Paginator(files, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'my_files.html', {'page_obj': page_obj})

@login_required
def create_link(request, file_id):
    file = get_object_or_404(EncryptedFile, id=file_id, owner=request.user)
    
    if request.method == 'POST':
        form = ShareableLinkForm(request.POST)
        if form.is_valid():
            link = form.save(commit=False)
            link.file = file
            link.generate_token()
            link.expires_at = timezone.now() + timedelta(hours=form.cleaned_data['expiry_hours'])
            
            if link.password_protected and link.access_password:
                link.access_password = hashlib.sha256(link.access_password.encode()).hexdigest()
            
            link.save()
            
            allowed_emails = request.POST.get('allowed_emails', '').strip()
            if allowed_emails:
                for email in allowed_emails.split(','):
                    email = email.strip()
                    if email:
                        AccessPermission.objects.create(link=link, allowed_email=email)
            
            ActivityLog.objects.create(
                user=request.user,
                activity_type='link_created',
                file=file,
                link=link,
                details=f"Created link for {file.original_filename}"
            )
            
            messages.success(request, 'Shareable link created successfully!')
            return redirect('link_details', link_id=link.id)
    else:
        form = ShareableLinkForm()
    
    return render(request, 'create_link.html', {'form': form, 'file': file})

@login_required
def my_links(request):
    links = ShareableLink.objects.filter(file__owner=request.user).order_by('-created_at')
    paginator = Paginator(links, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'my_links.html', {'page_obj': page_obj})

@login_required
def link_details(request, link_id):
    link = get_object_or_404(ShareableLink, id=link_id, file__owner=request.user)
    download_logs = ActivityLog.objects.filter(link=link, activity_type='download').order_by('-timestamp')
    full_url = request.build_absolute_uri(f'/download/{link.token}/')
    
    context = {
        'link': link,
        'full_url': full_url,
        'download_logs': download_logs,
    }
    return render(request, 'link_details.html', context)

def download_file(request, token):
    link = get_object_or_404(ShareableLink, token=token)
    
    if link.is_expired() or not link.is_active:
        return render(request, 'link_expired.html')
    
    if link.password_protected:
        if request.method == 'POST':
            password = request.POST.get('password', '')
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            if hashed_password != link.access_password:
                messages.error(request, 'Incorrect password')
                return render(request, 'download_password.html', {'link': link})
        else:
            return render(request, 'download_password.html', {'link': link})
    
    permissions = link.permissions.all()
    if permissions.exists():
        user_email = request.GET.get('email', '')
        if not permissions.filter(allowed_email=user_email).exists():
            return render(request, 'access_denied.html')
    
    file = link.file
    file_path = os.path.join(settings.MEDIA_ROOT, 'encrypted', file.encrypted_filename)
    
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    encryptor = FileEncryption(settings.ENCRYPTION_KEY)
    decrypted_data = encryptor.decrypt_file(encrypted_data, bytes(file.encryption_iv))
    
    if not FileEncryption.verify_hash(decrypted_data, file.file_hash):
        return HttpResponse('File integrity check failed', status=500)
    
    link.download_count += 1
    link.save()
    
    ActivityLog.objects.create(
        user=file.owner,
        activity_type='download',
        file=file,
        link=link,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        details=f"Downloaded {file.original_filename}"
    )
    
    Notification.objects.create(
        user=file.owner,
        notification_type='file_downloaded',
        title='File Downloaded',
        message=f'Your file "{file.original_filename}" was downloaded'
    )
    
    response = HttpResponse(decrypted_data, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{file.original_filename}"'
    return response

@login_required
def activity_logs(request):
    logs = ActivityLog.objects.filter(user=request.user).order_by('-timestamp')
    paginator = Paginator(logs, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'activity_logs.html', {'page_obj': page_obj})

@login_required
def notifications(request):
    notifications = Notification.objects.filter(user=request.user)
    
    if request.method == 'POST':
        notif_id = request.POST.get('notification_id')
        if notif_id:
            Notification.objects.filter(id=notif_id, user=request.user).update(is_read=True)
            return JsonResponse({'status': 'success'})
    
    return render(request, 'notifications.html', {'notifications': notifications})

@login_required
def analytics(request):
    uploads_by_day = ActivityLog.objects.filter(
        user=request.user,
        activity_type='upload',
        timestamp__gte=timezone.now() - timedelta(days=30)
    ).extra({'day': 'date(timestamp)'}).values('day').annotate(count=Count('id'))
    
    downloads_by_day = ActivityLog.objects.filter(
        user=request.user,
        activity_type='download',
        timestamp__gte=timezone.now() - timedelta(days=30)
    ).extra({'day': 'date(timestamp)'}).values('day').annotate(count=Count('id'))
    
    most_downloaded = ActivityLog.objects.filter(
        user=request.user,
        activity_type='download',
        file__isnull=False
    ).values('file__original_filename').annotate(count=Count('id')).order_by('-count')[:5]
    
    context = {
        'uploads_by_day': list(uploads_by_day),
        'downloads_by_day': list(downloads_by_day),
        'most_downloaded': list(most_downloaded),
    }
    return render(request, 'analytics.html', context)

@login_required
def delete_file(request, file_id):
    file = get_object_or_404(EncryptedFile, id=file_id, owner=request.user)
    
    if request.method == 'POST':
        file_path = os.path.join(settings.MEDIA_ROOT, 'encrypted', file.encrypted_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        profile = request.user.userprofile
        profile.storage_used -= file.file_size
        profile.save()
        
        file.is_active = False
        file.save()
        
        messages.success(request, 'File deleted successfully')
        return redirect('my_files')
    
    return render(request, 'confirm_delete.html', {'file': file})

@login_required
def deactivate_link(request, link_id):
    link = get_object_or_404(ShareableLink, id=link_id, file__owner=request.user)
    link.is_active = False
    link.save()
    messages.success(request, 'Link deactivated successfully')
    return redirect('my_links')

@login_required
def admin_dashboard(request):
    if not request.user.userprofile.is_admin:
        messages.error(request, 'Access denied')
        return redirect('dashboard')
    
    total_users = User.objects.count()
    total_files = EncryptedFile.objects.filter(is_active=True).count()
    total_storage = EncryptedFile.objects.filter(is_active=True).aggregate(Sum('file_size'))['file_size__sum'] or 0
    recent_activities = ActivityLog.objects.all()[:20]
    
    context = {
        'total_users': total_users,
        'total_files': total_files,
        'total_storage': total_storage,
        'recent_activities': recent_activities,
    }
    return render(request, 'admin_dashboard.html', context)

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip