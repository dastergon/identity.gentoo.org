from django import forms

class PasswordForm(forms.Form):
    old_password = forms.CharField(max_length = 30, widget = forms.PasswordInput(), label = 'Old password:')
    password1 = forms.CharField(max_length = 30, widget = forms.PasswordInput(), label = 'New Password:')
    password2 = forms.CharField(max_length = 30, widget = forms.PasswordInput(), label = 'Verify Password:')
