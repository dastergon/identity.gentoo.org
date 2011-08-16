from django import forms

class OkupyMultiWidget(forms.MultiWidget):
    def __init__(self, attrs=None):
        widgets = []
        while len(widgets) < 10:
            widgets.append(forms.TextInput(attrs=attrs))
        widgets = tuple(widgets)
        super(OkupyMultiWidget, self).__init__(widgets, attrs)

    def decompress(self, value):
        if value:
            return value.split('::')
        return ['']
