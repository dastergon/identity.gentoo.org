from django import forms
from identity.accounts.widgets import OkupyMultiWidget

class OkupyMultiField(forms.MultiValueField):
    widget = OkupyMultiWidget

    def __init__(self, *args, **kwargs):
        fields = []
        while len(fields) < 10:
            fields.append(forms.CharField())
        fields = tuple(fields)
        super(OkupyMultiField, self).__init__(fields, *args, **kwargs)

    def compress(self, data_list):
        if data_list:
            return '::'.join(data_list)
        return ''
