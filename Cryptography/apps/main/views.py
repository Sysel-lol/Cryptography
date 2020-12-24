import requests
import json

from django.shortcuts import render, redirect, reverse
from django.http import HttpResponse, JsonResponse
from django.views import View
from django.views.generic.edit import FormView
from django.views.generic.detail import DetailView

from Cryptography.apps.main import forms, models


class IndexView2(View):
    """
    Used for both rendering the object creating form and an object use.
    """
    input_form_class = forms.InputForm
    input_form = forms.InputForm()
    cryptography_object_form = None

    def get(self, request, object_id=None):

        cryptography_object_list = models.CryptographyObject.objects.all()

        if object_id:
            cryptography_object_instance = models.CryptographyObject.objects.filter(id=object_id).first()
            if not cryptography_object_instance:
                return redirect("main:index")
            cryptography_object_form = self.cryptography_object_form if self.cryptography_object_form \
                else forms.CryptographyObjectForm(instance=cryptography_object_instance)
            cryptography_object_form.fields['cipher'].queryset = models.Cipher.objects.filter(
                is_asymmetric=cryptography_object_form.instance.cipher.is_asymmetric)
            return render(request, 'main/object.html', {
                'cryptography_object_form': cryptography_object_form,
                'input_form': self.input_form,
                'object_id': object_id,
                'cryptography_object_list': cryptography_object_list
            })
        else:
            cryptography_object_form = self.cryptography_object_form if self.cryptography_object_form \
                else forms.CryptographyObjectForm(instance=models.CryptographyObject())
            symmetric_queryset = models.Cipher.objects.filter(is_asymmetric=False)
            symmetric_cryptography_object_form = forms.CryptographyObjectForm(
                instance=models.CryptographyObject(cipher=symmetric_queryset.first()))
            symmetric_cryptography_object_form.fields['cipher'].queryset = symmetric_queryset
            cryptography_object_form.fields['cipher'].queryset = models.Cipher.objects.filter(is_asymmetric=True)
            return render(request, 'main/index.html', {
                'cryptography_object_form': cryptography_object_form,
                'symmetric_cryptography_object_form': symmetric_cryptography_object_form,
                'cryptography_object_list': cryptography_object_list
            })

    def post(self, request, object_id=None):
        cryptography_object_instance = models.CryptographyObject()
        if object_id:
            cryptography_object_instance = models.CryptographyObject.objects.filter(id=object_id).first()
            if not cryptography_object_instance:
                return redirect("main:index")
        if request.POST.get():
            cryptography_object_form = forms.CryptographyObjectForm(
                request.POST.copy(), instance=cryptography_object_instance, files=request.FILES)
            if cryptography_object_form.is_valid():
                cryptography_object = cryptography_object_form.save()
                return redirect("main:index", object_id=cryptography_object.id)
            self.cryptography_object_form = cryptography_object_form
        elif request.POST.get():
            keys = cryptography_object_instance.get_keys()
            self.input_form = self.input_form_class(request.POST)
            if self.input_form.is_valid():
                input_data = self.input_form.cleaned_data['input']
                if request.POST.get() == "encrypt":
                    key = keys[1] if cryptography_object_instance.cipher.is_asymmetric else keys[0]
                    try:
                        output_data = cryptography_object_instance.cipher.engine.encrypt(
                            input_data, key)
                    except Exception as e:
                        output_data = "Произошла ошибка при зашифровывании исходных данных."+str(e)
                elif request.POST.get() == "decrypt":
                    key = keys[0]
                    try:
                        output_data = cryptography_object_instance.cipher.engine.decrypt(
                            input_data, key)
                    except Exception as e:
                        output_data = "Произошла ошибка при расшифровывании исходных данных."+str(e)

                self.input_form = forms.InputForm({
                    'input': input_data,
                    'output': output_data
                })
        return self.get(request, object_id)


class IndexView(FormView):
    template_name = 'main/index.html'
    form_class = forms.CryptographyObjectForm
    object_id = None

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

    def form_valid(self, form):
        cryptography_object = form.save()
        self.object_id = cryptography_object.id
        return super(IndexView, self).form_valid(form)

    def get_success_url(self):
        return reverse('main:cryptography_object', kwargs={'object_id': self.object_id})


class CryptographyObjectView(DetailView):
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
        context_data['cryptography_object_list'] = self.model.objects.all()
        return context_data

    def post(self, *args, **kwargs):
        get_response = self.get(*args, **kwargs)
        if not self.input_form.is_valid():
            return get_response
        keys = self.object.get_keys()
        input_data = self.input_form.cleaned_data['input']
        if self.request.POST.get('process_input') == "encrypt":
            key = keys[1] if self.object.cipher.is_asymmetric else keys[0]
            try:
                output_data = self.object.cipher.engine.encrypt(
                    input_data, key)
            except Exception as e:
                output_data = "Произошла ошибка при зашифровывании исходных данных." + str(e)
        elif self.request.POST.get('process_input') == "decrypt":
            key = keys[0]
            try:
                output_data = self.object.cipher.engine.decrypt(
                    input_data, key)
            except Exception as e:
                output_data = "Произошла ошибка при расшифровывании исходных данных." + str(e)

        self.input_form = self.input_form_class({
            'input': input_data,
            'output': output_data
        })

        return self.get(*args, **kwargs)


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
    cipher_key_length_relation_id = request.GET.get()
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