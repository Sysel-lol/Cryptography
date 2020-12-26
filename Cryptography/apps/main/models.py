import re
import hashlib
import base64

from django.db import models
from django.db.models.signals import post_init, pre_save
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.utils.encoding import escape_uri_path
from django.shortcuts import reverse

from Cryptography.settings import SECRET_KEY
from Cryptography.apps.main import adapters


class CipherKeyLength(models.Model):
    """
    A table with possible key lengths used in ciphers.
    It's used for key_length field of Cipher class.
    """
    CHOICES = [
        (0, 'Любая'),
        (64, '64'),
        (128, '128'),
        (256, '256'),
        (512, '512')
    ]

    length = models.SmallIntegerField('Длинна ключа', choices=CHOICES, default=0)

    def __str__(self):
        result = [alias[1] for alias in self.CHOICES if alias[0] == self.length]
        return result[0]


class Cipher(models.Model):
    """
    Represents cipher object in the project.
    """
    name = models.CharField('Название шифра', max_length=128)
    is_asymmetric = models.BooleanField('Тип', choices=[
        (False, 'Симметричный'),
        (True, 'Ассиметричный')
    ])
    key_lengths = models.ManyToManyField(CipherKeyLength, through="CipherKeyLengthRelation")

    _CIPHER_ENGINES = {
        'AES': adapters.AESAdapter(),
        'RSA': adapters.RSAAdapter(),
        'FERNET': adapters.FernetAdapter(),
        'PAILLIER': adapters.PaillierAdapter()
    }

    @staticmethod
    def get_cipher_engine(name: str):
        name = name.upper()
        if name in Cipher._CIPHER_ENGINES:
            return Cipher._CIPHER_ENGINES[name]
        return False

    @property
    def engine(self):
        """
        Returns an object of a cipher class to work with.
        :return: ICipher interface inherited object
        """
        return Cipher.get_cipher_engine(self.name)

    def __str__(self):
        return self.name


class CipherKeyLengthRelation(models.Model):
    """
    Used for making a relation between Cipher class and CipherKeyLength class.
    """
    cipher = models.ForeignKey(Cipher, on_delete=models.DO_NOTHING)
    cipher_key_length = models.ForeignKey(CipherKeyLength, on_delete=models.DO_NOTHING)

    def __str__(self):
        return str(self.cipher_key_length)


class CryptographyObject(models.Model):
    """
    The main class of the project. It unites all all necessary data for creating a cryptography object.
    """
    DEFAULT_CIPHER_ID = 1
    DEFAULT_KEY_LENGTH_ID = 1

    old_state = 0

    name = models.CharField('Название объекта', max_length=128)
    cipher = models.ForeignKey(Cipher, on_delete=models.DO_NOTHING, default=DEFAULT_CIPHER_ID, verbose_name='Шифр')
    key_length = models.ForeignKey(
        CipherKeyLengthRelation, default=DEFAULT_KEY_LENGTH_ID, on_delete=models.DO_NOTHING, verbose_name='Длина ключа')
    private_key = models.TextField('Закрытый ключ')
    public_key = models.TextField('Открытый ключ', blank=True, null=True)

    def export_to_file(self, public_key: bool = 0):
        """
        Export keys to a file.
        :param public_key: bool. If it's true, then a public key will be exported, otherwise a private key.
        :return: File with a key to download
        """
        label = "private key"
        public_key = bool(public_key)
        file_content = None
        if not public_key:
            file_content = b"-----BEGIN " + str(self.cipher).upper().encode('utf8') + b" PRIVATE KEY-----\n" \
                            + self.cipher.engine.compose_file_data(self.private_key) \
                            + b"\n-----END " + str(self.cipher).upper().encode('utf8') + b" PRIVATE KEY-----"
        elif self.cipher.is_asymmetric:
            file_content = b"-----BEGIN " + str(self.cipher).upper().encode('utf8') + b" PUBLIC KEY-----\n" \
                            + self.cipher.engine.compose_file_data(self.public_key) \
                            + b"\n-----END " + str(self.cipher).upper().encode('utf8') + b" PUBLIC KEY-----"
            if public_key:
                label = "public_key"
        if not file_content:
            return HttpResponse('Не удалось экспортировать ключ.')
        response = HttpResponse(file_content.decode('utf8'), content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment; filename="'+ \
                                          escape_uri_path(str(self.name)+' ('+str(self.cipher)+', '+label+').pem')+'"'
        return response

    def get_keys(self):
        """
        Getting keys. You have to use this one instead of direct accessing the fields to make sure you get right keys.
        Always returns private key and public key (if a cipher is symmetric, then the second one will be None).
        :return: private_key, public_key
        """
        if self.cipher.is_asymmetric:
            return self.private_key, self.public_key
        else:
            return self.private_key, None

    def parse_file(self, file_data: bytes):
        if isinstance(file_data, str):
            file_data = file_data.encode('utf8')
        re_object = re.compile(
            b"-----BEGIN (.+) (PRIVATE|PUBLIC) KEY-----\n" + b"(.+)" + b"\n-----END (.+) (PRIVATE|PUBLIC) KEY-----",
            re.DOTALL)
        result = re_object.findall(file_data)
        if not result or result[0][0] != result[0][3] or result[0][1] != result[0][4]:
            raise Exception('Файл ключа поврежден.')
        cipher_name = result[0][0].decode('utf8')
        key_type = result[0][1].decode('utf8')
        cipher = Cipher.objects.filter(name__iexact=cipher_name).first()
        if not cipher:
            raise Exception('Шифр данного ключа не поддерживается.')
        key = cipher.engine.parse_file_data(result[0][2])
        self.cipher = cipher
        if key_type == "PUBLIC":
            self.public_key = key
        elif key_type == "PRIVATE":
            self.private_key = key
        return cipher

    def clean_private_key(self):
        """
        Private key validator
        :return: private_key
        """
        private_key, public_key = self.get_keys()
        try:
            private_key = self.cipher.engine.str_to_key(private_key=private_key)
        except Exception as error:
            raise ValidationError('Введен неверный закрытый ключ.')
        if not private_key:
            raise ValidationError('Введен неверный закрытый ключ')
        key_length = self.cipher.engine.determine_key_length(private_key)
        cipher_key_length = CipherKeyLength.objects.filter(length=key_length).first()
        if not cipher_key_length:
            raise ValidationError('Введенный ключ имеет недопустимую разрядность.')
        cipher_key_length_relation = CipherKeyLengthRelation.objects.filter(
            cipher_id=self.cipher.id, cipher_key_length_id=cipher_key_length.id).first()
        if not cipher_key_length_relation:
            raise ValidationError('Выбранный шифр не поддерживает данную разрядность закрытого ключа.')
        self.key_length = cipher_key_length_relation
        return self.private_key

    def clean_public_key(self):
        """
        Public key validator.
        :return: public_key
        """
        if not self.cipher.is_asymmetric:
            return
        private_key, public_key = self.get_keys()
        try:
            public_key = self.cipher.engine.str_to_key(public_key=public_key)
        except Exception as error:
            raise ValidationError('Введен неверный открытый ключ.')
        if not public_key:
            raise ValidationError('Введен неверный открытый ключ')
        key_length = self.cipher.engine.determine_key_length(public_key)
        cipher_key_length = CipherKeyLength.objects.filter(length=key_length).first()
        if not cipher_key_length:
            raise ValidationError('Введенный ключ имеет недопустимую разрядность.')
        cipher_key_length_relation = CipherKeyLengthRelation.objects.filter(
            cipher_id=self.cipher.id, cipher_key_length_id=cipher_key_length.id).first()
        if not cipher_key_length_relation:
            raise ValidationError('Выбранный шифр не поддерживает данную разрядность открытого ключа.')
        if self.key_length != cipher_key_length_relation:
            raise ValidationError('Ключи имеют разную разрядность.')
        return self.public_key

    def clean(self):
        if not self.public_key and not self.private_key:
            return
        self.clean_private_key()
        self.clean_public_key()
        private_key, public_key = self.get_keys()
        if not private_key and not public_key:
            raise ValidationError('Введены некорректные ключи.')

    @property
    def get_key_length(self):
        return self.key_length.cipher_key_length.length

    @property
    def fingerprint(self):
        """
        Returns public key fingerprint for asymmetric ciphers.
        :return:
        """
        public_key = str(self.get_keys()[1])
        if self.cipher.is_asymmetric and public_key:
            return "SHA512: "+hashlib.sha512(public_key.encode('utf8')).hexdigest()
        return False

    @property
    def is_asymmetric(self):
        return self.cipher.is_asymmetric

    @staticmethod
    def post_init(**kwargs):
        """
        Necessary actions after cryptography object initialization, connected via post_init.connect function below.
        """
        instance = kwargs.get('instance')
        if not instance.cipher.is_asymmetric:
            instance.key_length = CipherKeyLengthRelation.objects.filter(cipher_id=instance.cipher.id).first()
        if any(instance.get_keys()):
            return
        instance.key_length = CipherKeyLengthRelation.objects.filter(cipher_id=instance.cipher.id).first()
        if instance.cipher.is_asymmetric:
            new_keys = instance.cipher.engine.new_keys(instance.get_key_length)
        else:
            secret_key_bytes = SECRET_KEY.encode('utf8')[:32]
            new_private_key = base64.urlsafe_b64encode(secret_key_bytes).decode('utf8')
            new_keys = (new_private_key, None)
        instance.private_key, instance.public_key = new_keys

    @staticmethod
    def pre_save(**kwargs):
        """
            Necessary actions before cryptography object saving, connected via pre_save.connect function below.
        """
        instance = kwargs.get('instance')
        if not instance.cipher.is_asymmetric:
            instance.public_key = None

    def get_absolute_url(self):
        return reverse('main:cryptography_object', kwargs={'object_id': self.id})

    def __str__(self):
        return self.name


post_init.connect(CryptographyObject.post_init, CryptographyObject)
pre_save.connect(CryptographyObject.pre_save, CryptographyObject)

