# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django import forms

from .models import OpenID_Attributes


class LoginForm(forms.Form):
    username = forms.CharField(max_length=100, label='Username:')
    password = forms.CharField(max_length=30, widget=forms.PasswordInput(),
                               label='Password:')


class OpenIDLoginForm(LoginForm):
    auto_logout = forms.BooleanField(required=False,
        label='Log out after answering the OpenID request')


class SSLCertLoginForm(forms.Form):
    session_id = forms.CharField(max_length=200, widget=forms.HiddenInput())
    next = forms.CharField(max_length=254, widget=forms.HiddenInput())
    login_uri = forms.CharField(max_length=254, widget=forms.HiddenInput())


class OTPForm(forms.Form):
    otp_token = forms.CharField(max_length=10, label='OTP token:')


class SignupForm(forms.Form):
    first_name = forms.CharField(max_length=100, label='First Name:')
    last_name = forms.CharField(max_length=100, label='Last Name:')
    email = forms.EmailField(max_length=254, label='Email: ')
    username = forms.CharField(max_length=100, label='Username:')
    password_origin = forms.CharField(
        max_length=30, widget=forms.PasswordInput(), label='Password:')
    password_verify = forms.CharField(
        max_length=30, widget=forms.PasswordInput(), label='Verify Password:')


# OpenID forms.

class SiteAuthForm(forms.ModelForm):
    class Meta:
        model = OpenID_Attributes
        exclude = ('trust_root', 'uid')
        widgets = {
            'nickname': forms.CheckboxInput,
            'email': forms.CheckboxInput,
            'fullname': forms.CheckboxInput,
            'dob': forms.CheckboxInput,
            'gender': forms.CheckboxInput,
            'postcode': forms.CheckboxInput,
            'country': forms.CheckboxInput,
            'language': forms.CheckboxInput,
            'timezone': forms.CheckboxInput,

            'which_email': forms.Select,
        }
