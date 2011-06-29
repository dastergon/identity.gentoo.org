from django import forms

class LoginForm(forms.Form):
    mail = forms.CharField(max_length = 254, label = 'Email:')
    password = forms.CharField(max_length = 30, widget = forms.PasswordInput(), label = 'Password:')
    remember = forms.BooleanField(required = False, label = 'Remember Me')
