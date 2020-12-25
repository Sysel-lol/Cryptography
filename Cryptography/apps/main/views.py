import requests
import json

from django.shortcuts import render, redirect, reverse
from django.http import HttpResponse, JsonResponse
from django.views.generic.edit import UpdateView, CreateView
from django.views.generic.detail import DetailView

from Cryptography.apps.main import forms, models


class IndexView(CreateView):
    """
    The main page of the project, where you are suggested creating a new CryptographyObject
    for data encryption/decryption.
    """
    template_name = 'main/index.html'
    form_class = forms.CryptographyObjectForm

    def get_context_data(self, **kwargs):
        context_data = super(IndexView, self).get_context_data(**kwargs)

        symmetric_queryset = models.Cipher.objects.filter(is_asymmetric=False)
        symmetric_cryptography_object_form = forms.CryptographyObjectForm(
            instance=models.CryptographyObject(cipher=symmetric_queryset.first()))
        symmetric_cryptography_object_form.fields['cipher'].queryset = symmetric_queryset

        context_data['cryptography_object_form'] = context_data['form']
        context_data['cryptography_object_form'].fields['cipher'].queryset = models.Cipher.objects.filter(is_asymmetric=True)
        context_data['symmetric_cryptography_object_form'] = symmetric_cryptography_object_form
        context_data['cryptography_object_list'] = models.CryptographyObject.objects.all()

        return context_data

    def get_form_kwargs(self):
        kwargs = super(IndexView, self).get_form_kwargs()
        if self.request.FILES:
            kwargs['files'] = self.request.FILES
        return kwargs

    def get_success_url(self):
        return reverse('main:cryptography_object', kwargs={'object_id': self.object.id})


class CryptographyObjectView(DetailView):
    """
    Used both for CryptographyObject display and encryption/decryption of data.
    """
    template_name = 'main/object.html'
    input_form_class = forms.InputForm
    input_form = None
    model = models.CryptographyObject
    slug_field = 'pk'
    slug_url_kwarg = 'object_id'

    def get(self, *args, **kwargs):
        if not self.input_form:
            if self.request.method == 'POST':
                self.input_form = self.input_form_class(self.request.POST)
            else:
                self.input_form = self.input_form_class()
        return super(CryptographyObjectView, self).get(*args, **kwargs)

    def get_context_data(self, **kwargs):
        context_data = super(CryptographyObjectView, self).get_context_data(**kwargs)
        context_data['cryptography_object_form'] = forms.CryptographyObjectForm(instance=self.object)
        context_data['input_form'] = self.input_form
        context_data['object_id'] = self.object.id
        context_data['cryptography_object_list'] = self.model.objects.all()
        return context_data

    def post(self, *args, **kwargs):
        get_response = self.get(*args, **kwargs)
        if not self.input_form.is_valid():
            return get_response
        input_data = self.input_form.cleaned_data['input']
        output_data = ''
        if self.request.POST.get('process_input') == "encrypt":
            key = self.object.public_key if self.object.cipher.is_asymmetric else self.object.private_key
            try:
                output_data = self.object.cipher.engine.encrypt(
                    input_data, key)
            except Exception as e:
                output_data = "Произошла ошибка при зашифровывании исходных данных." + str(e)
        elif self.request.POST.get('process_input') == "decrypt":
            try:
                output_data = self.object.cipher.engine.decrypt(
                    input_data, self.object.private_key)
            except Exception as e:
                output_data = "Произошла ошибка при расшифровывании исходных данных." + str(e)

        self.input_form = self.input_form_class({
            'input': input_data,
            'output': output_data
        })

        return self.get(*args, **kwargs)


class CryptographyObjectUpdate(UpdateView):
    """
    Used for updating of a CryptographyObject.
    """
    model = models.CryptographyObject
    slug_field = 'pk'
    slug_url_kwarg = 'object_id'
    fields = '__all__'

    def get_success_url(self):
        return reverse('main:cryptography_object', kwargs={'object_id': self.object.id})


def export_key(request, object_id=None, public_key=False):
    """
    Used to export keys. If public_key is False, returns private key file, otherwise public key file.
    :param request:
    :param object_id: int
    :param public_key: bool
    :return:
    """
    cryptography_object = models.CryptographyObject.objects.filter(id=object_id).first()
    if not cryptography_object:
        redirect("main:index")
    return cryptography_object.export_to_file(public_key)


def generate_keys(request):
    """
    Used by AJAX for generating new keys without page refresh.
    """
    if request.method != "GET" or not request.is_ajax():
        return HttpResponse('')
    cipher_key_length_relation_id = request.GET.get('cipher_key_length_relation_id')
    if not cipher_key_length_relation_id:
        cipher_key_length_relation_id = 0
    cipher_key_length_relation = models.CipherKeyLengthRelation.objects.filter(id=cipher_key_length_relation_id).first()
    if not cipher_key_length_relation:
        return JsonResponse('Не могу определить длину ключа.')
    new_keys = cipher_key_length_relation.cipher.engine.new_keys(cipher_key_length_relation.cipher_key_length.length)
    return JsonResponse({'data': [str(new_keys[0]), str(new_keys[1])]})


def cipher_defaults(request):
    """
    Returns cipher available key lengths and new random keys for it.
    Used by AJAX when a user changes a cipher in the select element.
    """
    if request.method != "GET" or not request.is_ajax():
        return HttpResponse('')
    cipher_id = int(request.GET.get())
    cipher = models.Cipher.objects.filter(id=cipher_id).first()
    if not cipher:
        return JsonResponse('Шифр с данным ID не найден.')
    form = forms.CryptographyObjectForm(instance=models.CryptographyObject(cipher=cipher))
    return JsonResponse({
        'key_length': str(form['key_length'].label)+": "+str(form['key_length']),
        'private_key': str(form['private_key'].label)+"<br>"+str(form['private_key']),
        'public_key': str(form['public_key'].label)+"<br>"+str(form['public_key']),
        'fingerprint': str(form.instance.fingerprint)
    })


def create_cipher(request):
    form = forms.CipherForm()
    if request.method == "POST":
        form = forms.CipherForm(request.POST)
        if form.is_valid():
            form.save()
    return render(request, 'main/create_cipher.html', {'form': form})


def get_user_info(request):
    user_info = requests.get("https://randomuser.me/api/").json()
    user_info_json = json.dumps(user_info, indent=2, sort_keys=True)
    user_info_json = user_info_json.replace('\n', '<br>')
    user_info_json = user_info_json.replace(' ', '⠀')
    return render(request, 'main/user_block.html',
                  {'user_info': user_info['results'][0], 'user_info_json': user_info_json})