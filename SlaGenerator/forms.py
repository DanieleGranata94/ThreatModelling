from django import forms

from SlaGenerator.models import MACM


class MACMForm(forms.ModelForm):
    class Meta:
        model = MACM
        fields = ['appId','application']