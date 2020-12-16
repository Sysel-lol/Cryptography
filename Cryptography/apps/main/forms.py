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
            instance.is_file = True
            key_files = {}
            for field_name in files:
                fs = FileSystemStorage()
                filename = fs.save(files[field_name].name, files[field_name])
                uploaded_file_url = fs.path(filename)
                instance.set_keys(**{field_name: str(uploaded_file_url)})
            try:
                instance.full_clean(exclude=['name'])
            except ValidationError as error:
                fs = FileSystemStorage()
                for file in key_files:
                    fs.delete(file)
                file_error = error
                instance = old_state

        if instance.is_file:
            self.base_fields['key_length'].disabled, self.base_fields['cipher'].disabled = True, True
        else:
            self.base_fields['key_length'].disabled, self.base_fields['cipher'].disabled = False, False

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

