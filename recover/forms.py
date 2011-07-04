from django import forms

class RecoverForm(forms.Form):
    email = forms.EmailField(max_length = 254, label = 'Email: ')
    username = forms.CharField(max_length = 100, label = 'Username:')