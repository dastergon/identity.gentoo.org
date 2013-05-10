from django import forms

class SignupForm(forms.Form):
    first_name = forms.CharField(max_length = 100, label = 'First Name:')
    last_name = forms.CharField(max_length = 100, label = 'Last Name:')
    '''
    254 chars according to RFC 3696 http://www.rfc-editor.org/errata_search.php?rfc=3696&eid=1690
    '''
    email = forms.EmailField(max_length = 254, label = 'Email: ')
    username = forms.CharField(max_length = 100, label = 'Username:')
    password1 = forms.CharField(max_length = 30, widget = forms.PasswordInput(), label = 'Password:')
    password2 = forms.CharField(max_length = 30, widget = forms.PasswordInput(), label = 'Verify Password:')


