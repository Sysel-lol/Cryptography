import copy

from django import forms
from django.core.files.storage import FileSystemStorage
from django.core.exceptions import ValidationError

from Cryptography.apps.main import models


class CryptographyObjectForm(forms.ModelForm):
    """
    Represents cryptography object form.
    Processes files sent with a form and attach them to a cryptography object, if it's valid.
    If there's no field value in GET or POST data, it uses instance values.
    """
    def __init__(self, *args, **kwargs):
        instance = kwargs['instance']

        files = kwargs.get('files')
        file_error = False
        if files:
            old_state = copy.deepcopy(instance)
            for field_name in files:
                file_data = next(files[field_name].chunks())
                try:
                    instance.parse_file(file_data)
                except Exception as error:
                    file_error = error
            if not file_error:
                try:
                    instance.full_clean(exclude=['name'])
                except (ValidationError, ValueError) as error:
                    file_error = error
                    instance = old_state
            else:
                instance = old_state

        if args:
            for field in self.base_fields:
                if field not in args[0] or not args[0][field] or self.base_fields[field].disabled:
                    args[0][field] = getattr(instance, field)

        super(CryptographyObjectForm, self).__init__(*args, **kwargs)
        if file_error:
            self.add_error(field=None, error=file_error)

        self.fields['key_length'].queryset = models.CipherKeyLengthRelation.objects.filter(cipher_id=self['cipher'].value())
        for visible_field in self.visible_fields():
            visible_field.field.widget.attrs['class'] = 'form-control'

    class Meta:
        model = models.CryptographyObject
        fields = "__all__"


class CipherForm(forms.ModelForm):
    class Meta:
        model = models.Cipher
        fields = "__all__"


class InputForm(forms.Form):
    input = forms.CharField(widget=forms.Textarea())
    output = forms.CharField(widget=forms.Textarea(), required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible_field in self.visible_fields():
            visible_field.field.widget.attrs['class'] = 'form-control'

