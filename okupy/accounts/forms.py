# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django import forms

from okupy.accounts.models import OpenID_Attributes
from okupy.crypto.ciphers import sessionrefcipher


class LoginForm(forms.Form):
    username = forms.CharField(max_length=100, label='Username:')
    password = forms.CharField(max_length=30, widget=forms.PasswordInput(),
                               label='Password:')


class StrongAuthForm(forms.Form):
    password = forms.CharField(max_length=30, widget=forms.PasswordInput(),
                               label='Password:')


class OpenIDLoginForm(LoginForm):
    auto_logout = forms.BooleanField(required=False,
        label='Log out after answering the OpenID request')


class SSLCertLoginForm(forms.Form):
    session = forms.CharField(max_length=200, widget=forms.HiddenInput())
    next = forms.CharField(max_length=254, widget=forms.HiddenInput())
    login_uri = forms.CharField(max_length=254, widget=forms.HiddenInput())

    def clean_session(self):
        try:
            return sessionrefcipher.decrypt(
                self.cleaned_data['session'])
        except ValueError:
            raise forms.ValidationError('Invalid session id')


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

    def clean_password_verify(self):
        cleaned_data = super(SignupForm, self).clean()
        password_origin = cleaned_data.get('password_origin')
        password_verify = cleaned_data.get('password_verify')
        if password_origin != password_verify:
            raise forms.ValidationError("Passwords don't match")
        return password_verify


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
