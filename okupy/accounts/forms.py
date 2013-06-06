# -*- coding: utf-8 -*-

from django import forms

class LoginForm(forms.Form):
    username = forms.CharField(max_length = 100, label = 'Username:')
    password = forms.CharField(max_length = 30, widget = forms.PasswordInput(), label = 'Password:')
    remember = forms.BooleanField(required = False, label = 'Remember Me')

class SignupForm(forms.Form):
    first_name = forms.CharField(max_length = 100, label = 'First Name:')
    last_name = forms.CharField(max_length = 100, label = 'Last Name:')
    email = forms.EmailField(max_length = 254, label = 'Email: ')
    username = forms.CharField(max_length = 100, label = 'Username:')
    password_origin = forms.CharField(max_length = 30, widget = forms.PasswordInput(), label = 'Password:')
    password_verify = forms.CharField(max_length = 30, widget = forms.PasswordInput(), label = 'Verify Password:')
