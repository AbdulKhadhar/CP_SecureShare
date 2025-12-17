from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid
import hashlib

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_admin = models.BooleanField(default=False)
    storage_used = models.BigIntegerField(default=0)
    storage_limit = models.BigIntegerField(default=1073741824)  # 1GB
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.username}'s Profile"

class EncryptedFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='files')
    original_filename = models.CharField(max_length=255)
    encrypted_filename = models.CharField(max_length=255)
    file_size = models.BigIntegerField()
    file_hash = models.CharField(max_length=64)
    encryption_iv = models.BinaryField()
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.original_filename} ({self.owner.username})"

class ShareableLink(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE, related_name='links')
    token = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    max_downloads = models.IntegerField(default=10)
    download_count = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    password_protected = models.BooleanField(default=False)
    access_password = models.CharField(max_length=128, blank=True, null=True)
    
    def is_expired(self):
        return timezone.now() > self.expires_at or self.download_count >= self.max_downloads
    
    def generate_token(self):
        unique_string = f"{self.file.id}{timezone.now().timestamp()}{uuid.uuid4()}"
        self.token = hashlib.sha256(unique_string.encode()).hexdigest()
    
    def __str__(self):
        return f"Link for {self.file.original_filename}"

class AccessPermission(models.Model):
    link = models.ForeignKey(ShareableLink, on_delete=models.CASCADE, related_name='permissions')
    allowed_email = models.EmailField()
    granted_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Permission for {self.allowed_email}"

class ActivityLog(models.Model):
    ACTIVITY_TYPES = [
        ('upload', 'File Upload'),
        ('download', 'File Download'),
        ('link_created', 'Link Created'),
        ('link_accessed', 'Link Accessed'),
        ('login', 'User Login'),
        ('logout', 'User Logout'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    activity_type = models.CharField(max_length=20, choices=ACTIVITY_TYPES)
    file = models.ForeignKey(EncryptedFile, on_delete=models.SET_NULL, null=True, blank=True)
    link = models.ForeignKey(ShareableLink, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    details = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.activity_type} - {self.timestamp}"

class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('link_expired', 'Link Expired'),
        ('file_downloaded', 'File Downloaded'),
        ('new_share', 'New File Shared'),
        ('storage_warning', 'Storage Warning'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=255)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.title} - {self.user.username}"