from django import forms

class SignupForm(forms.Form):
    first_name = forms.CharField(max_length = 100, label = 'First Name:')
    last_name = forms.CharField(max_length = 100, label = 'Last Name:')
    email = forms.EmailField(max_length = 100, label = 'Email: ')
    username = forms.CharField(max_length = 100, label = 'Username:')
    password1 = forms.CharField(max_length = 100, widget = forms.PasswordInput(), label = 'Password:')
    password2 = forms.CharField(max_length = 100, widget = forms.PasswordInput(), label = 'Verify Password:')


