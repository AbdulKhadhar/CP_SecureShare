from django import forms
from .models import ShareableLink

class FileUploadForm(forms.Form):
    file = forms.FileField(
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '*/*'
        })
    )

class ShareableLinkForm(forms.ModelForm):
    expiry_hours = forms.IntegerField(
        initial=24,
        min_value=1,
        max_value=720,
        widget=forms.NumberInput(attrs={'class': 'form-control'})
    )
    
    class Meta:
        model = ShareableLink
        fields = ['max_downloads', 'password_protected', 'access_password']
        widgets = {
            'max_downloads': forms.NumberInput(attrs={'class': 'form-control'}),
            'password_protected': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'access_password': forms.PasswordInput(attrs={'class': 'form-control'}),
        }