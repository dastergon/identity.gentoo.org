# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django import forms

from okupy.accounts.models import OpenID_Attributes
from okupy.crypto.ciphers import sessionrefcipher

import pytz


class LoginForm(forms.Form):
    username = forms.CharField(max_length=100, label='Username:')
    password = forms.CharField(max_length=30, widget=forms.PasswordInput(),
                               label='Password:')


class StrongAuthForm(forms.Form):
    password = forms.CharField(max_length=30, widget=forms.PasswordInput(),
                               label='Password:')


class OpenIDLoginForm(LoginForm):
    auto_logout = forms.BooleanField(
        required=False,
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


#Settings

class ProfileSettingsForm(forms.Form):
    first_name = forms.CharField(
        max_length=100, label='First Name', required=False)
    last_name = forms.CharField(
        max_length=100, label='Last Name', required=False)
    birthday = forms.DateField(
        input_formats='%m/%d/%Y', label='Birthday', required=False)
    timezone = forms.ChoiceField(
        choices=[(x, x) for x in pytz.common_timezones])


class PasswordSettingsForm(forms.Form):
    old_password = forms.CharField(max_length=30, widget=forms.PasswordInput(
    ), label='Old Password', required=False)
    new_password = forms.CharField(max_length=30, widget=forms.PasswordInput(
    ), label='New Password', required=False)
    new_password_verify = forms.CharField(max_length=30,
                                          widget=forms.PasswordInput(),
                                          label='Repeat New Password',
                                          required=False)

    def clean(self):
        cleaned_data = super(PasswordSettingsForm, self).clean()
        new_password = cleaned_data.get('new_password')
        new_password_verify = cleaned_data.get('new_password_verify')
        old_password = cleaned_data.get('old_password')
        if (new_password or new_password_verify) and (not old_password):
            raise forms.ValidationError(
                'Please enter your current password to change the password.')
        elif new_password != new_password_verify:
            raise forms.ValidationError(
                "Paswords don't match. Please enter passwords again.")
        elif (old_password and new_password) and (not new_password_verify):
            raise forms.ValidationError(
                'Password verification failed. Please repeat your passwords.')
        return cleaned_data


class EmailSettingsForm(forms.Form):
    email = forms.EmailField(max_length=254, label='Add Email',
                             help_text='A valid email address, please.',
                             required=False)
    gravatar = forms.EmailField(max_length=254, label='Gravatar Email',
                                required=False)


class ContactSettingsForm(forms.Form):
    website = forms.URLField(label='Website', required=False)
    im = forms.CharField(max_length=100, label='IM', required=False)
    location = forms.CharField(label='Location', required=False)
    longitude = forms.FloatField(label='Longitude', required=False)
    latitude = forms.FloatField(label='Latitude', required=False)
    phone = forms.CharField(label='Home Phone', required=False)
    gpg_fingerprint = forms.CharField(label='GPG Fingerprint', required=False)


class GentooAccountSettingsForm(forms.Form):
    gentoo_join_date = forms.CharField(
        label='Gentoo Join Date', required=False)
    gentoo_retire_date = forms.CharField(
        label='Gentoo Retire Date', required=False)
    developer_bug = forms.CharField(
        label='Developer Bugs (Bug Number)', required=False)
    mentor = forms.CharField(max_length=100, label='Mentor', required=False)
    planet_feed = forms.URLField(label='Gentoo Planet Feed', required=False)
    universe_feed = forms.URLField(
        label='Gentoo Universe Feed', required=False)


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
