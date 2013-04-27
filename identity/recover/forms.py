from django import forms

class RecoverInitForm(forms.Form):
    email = forms.EmailField(max_length = 254, label = 'Email: ')
    username = forms.CharField(max_length = 100, label = 'Username:')

class RecoverForm(forms.Form):
    password1 = forms.CharField(max_length = 30, widget = forms.PasswordInput(), label = 'Password:')
    password2 = forms.CharField(max_length = 30, widget = forms.PasswordInput(), label = 'Verify Password:')
