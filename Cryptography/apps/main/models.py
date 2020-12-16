import os
import re
import hashlib
import base64
from pathlib import Path

from django.db import models
from django.db.models.signals import post_init
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from Crypto.Cipher import AES
from phe import paillier
import rsa

from cryptography.fernet import Fernet
from Cryptography.settings import MEDIA_ROOT


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
    class_name = models.CharField('Имя класса', max_length=128)
    is_asymmetric = models.BooleanField('Тип', choices=[
        (False, 'Симметричный'),
        (True, 'Ассиметричный')
    ])
    key_lengths = models.ManyToManyField(CipherKeyLength, through="CipherKeyLengthRelation")

    @property
    def engine(self):
        """
        Returns an object of a cipher class to work with.
        :return: ICipher interface inherited object
        """
        return globals()[self.class_name]()

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
    DEFAULT_KEY_LENGTH_ID = 0

    old_state = 0

    name = models.CharField('Название объекта', max_length=128)
    cipher = models.ForeignKey(Cipher, on_delete=models.DO_NOTHING, default=DEFAULT_CIPHER_ID, verbose_name='Шифр')
    key_length = models.ForeignKey(
        CipherKeyLengthRelation, default=DEFAULT_KEY_LENGTH_ID, on_delete=models.DO_NOTHING, verbose_name='Длина ключа')
    private_key = models.TextField('Закрытый ключ')
    public_key = models.TextField('Открытый ключ', blank=True)
    is_file = models.BooleanField('Из файла', default=False)

    def export_to_file(self, public_key: bool = 0):
        """
        Export keys to a file.
        :param public_key: bool. If it's true, then a public key will be exported, otherwise a private key.
        :return: File with a key to download
        """
        label = "private key"
        public_key = bool(public_key)
        if not self.cipher.is_asymmetric:
            file_content = str(self.cipher.id)+"\n"+str(self.get_keys()[0])
        else:
            file_content = str(self.cipher.id) + "\n" + str(self.get_keys()[public_key])
            if public_key:
                label = "public_key"
        response = HttpResponse(file_content, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename="'+self.name+" ("+str(self.cipher)+', '+label+').key"'
        return response

    @property
    def file_name(self):
        """
        Returns file names of keys without path.
        :return: string: file name
        """
        if not self.is_file:
            return False
        if self.cipher.is_asymmetric:
            return Path(self.private_key).name, Path(self.public_key).name
        else:
            return Path(self.private_key).name, None

    def set_keys(self, private_key: str = None, public_key: str = None):
        """
        The method used to set cryptography object keys. You have to use this one instead of direct assignment, because
        it can lead to unforeseen consequences.
        :param private_key: private key to set.
        :param public_key: public key to set.
        :return: None
        """
        if self.is_file:
            key_path = private_key if private_key else public_key
            if not key_path:
                return False
            file = open(os.path.join(MEDIA_ROOT, key_path), 'r')
            cipher_id = file.readline()
            cipher = Cipher.objects.filter(id=cipher_id).first()
            if not cipher:
                raise Exception('Файл поврежден.')
            self.cipher = cipher

        if private_key:
            self.private_key = private_key
        if public_key:
            self.public_key = public_key
        if public_key and not self.cipher.is_asymmetric:
            self.private_key = public_key

    def get_keys(self):
        """
        Getting keys. You have to use this one instead of direct accessing the fields to make sure you get right keys.
        Always returns private key and public key (if a cipher is symmetric, then the second one will be None).
        :return: private_key, public_key
        """
        if self.cipher.is_asymmetric:
            if self.is_file:
                return self.import_key_from_file(self.private_key), self.import_key_from_file(self.public_key)
            return self.private_key, self.public_key
        else:
            if self.is_file:
                return self.import_key_from_file(self.private_key), None
            return self.private_key, None

    @staticmethod
    def import_key_from_file(file: str):
        """
        Used for reading keys in files. Also sets cipher for current cryptography object depending on file data.
        :param file: full name of a file (with path).
        :return: key: str
        """
        try:
            file = open(file, 'r')
        except Exception:
            return None
        cipher_id = file.readline()
        cipher = Cipher.objects.filter(id=cipher_id).first()
        if not cipher:
            raise Exception('Файл поврежден.')
        key = file.readline()
        if not key:
            raise Exception('Файл поврежден.')
        file.close()
        return ''.join(key)

    def clean_private_key(self):
        """
        Private key validator
        :return: private_key
        """
        private_key, public_key = self.get_keys()
        private_key = self.cipher.engine.str_to_key(private_key=private_key)
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
        public_key = self.cipher.engine.str_to_key(public_key=public_key)
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
        if any(instance.get_keys()) or instance.is_file:
            return
        instance.key_length = CipherKeyLengthRelation.objects.filter(cipher_id=instance.cipher.id).first()
        new_keys = instance.cipher.engine.new_keys(instance.get_key_length)
        instance.set_keys(*new_keys)

    def __str__(self):
        return self.name


post_init.connect(CryptographyObject.post_init, CryptographyObject)


class ICipher:
    """
    Interface for ciphers. Any cipher class used in the project have to both inherit from this one and implement
    it's methods for the correct work. Also each cipher key class should have correct __str__ method defined to convert
    actual keys into strings.
    """
    def new_keys(self, length: int):
        """
        A method used to generate new random private and public keys.
        Always returns couple private_key, public_key. If a cipher is symmetric, the public_key sets to None.
        :param length: key length of both keys
        :return: private_key, public key
        """
        pass

    def encrypt(self, plain_text: str, key: str):
        """
        Used to encrypt data with a current cipher. At first should use str_to_key method to convert string with key
        to an actual key.
        :param plain_text: str
        :param key: str
        :return: cipher text: str
        """
        pass

    def decrypt(self, cipher_text: str, key: str):
        """
        Used to decrypt data with a current cipher. At first should use str_to_key method to convert string with key
        to an actual key.
        :param cipher_text: str
        :param key: str
        :return: plain text: str
        """
        pass

    @staticmethod
    def determine_key_length(key: str):
        """
        Used to determine key length in bits.
        :param key: str
        :return: n: int
        """
        pass

    @staticmethod
    def str_to_key(private_key: str, public_key: str):
        """
        Converts strings with keys to actual keys.
        :param private_key: str
        :param public_key: str
        :return: [private_key], [public_key]
        """
        pass


class RSAAdapter(ICipher):

    def new_keys(self, length):
        new_keys = rsa.newkeys(length)
        return new_keys[1], new_keys[0]

    def encrypt(self, plain_text, key):
        public_key = self.str_to_key(public_key=key)
        plain_text = plain_text.encode('utf8')
        pos = 0
        block_length = int(public_key.n).bit_length()//8-11
        result = ""
        while pos < len(plain_text):
            plain_text_block = plain_text[pos:pos+block_length]
            result += rsa.encrypt(plain_text_block, public_key).hex()+' '
            pos += block_length
        return result

    def decrypt(self, cipher_text, key):
        private_key = self.str_to_key(private_key=key)
        if cipher_text[len(cipher_text) - 1] != ' ':
            cipher_text += ' '
        block_start, block_end = 0, cipher_text.find(' ')
        result = ""
        while block_end != -1:
            cipher_text_block = bytes.fromhex(cipher_text[block_start:block_end])
            result += rsa.decrypt(cipher_text_block, private_key).decode(encoding='utf8')
            block_start, block_end = block_end, cipher_text.find(' ', block_end + 1)
        return result

    @staticmethod
    def determine_key_length(key):
        if not key:
            return False
        if not isinstance(key, rsa.PublicKey) and not isinstance(key, rsa.PrivateKey):
            return False
        return key.n.bit_length()

    @staticmethod
    def str_to_key(private_key=None, public_key=None):
        if not private_key and not public_key:
            return False
        private_key_instance = None

        if private_key:
            nedpq = re.findall(r'PrivateKey\(([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+)', private_key)
            if nedpq:
                n, e, d, p, q, = nedpq[0]
                if all([n, e, d, p, q]):
                    private_key_instance = rsa.PrivateKey(int(n), int(e), int(d), int(p), int(q))

        public_key_instance = None

        if public_key:
            ne = re.findall(r'PublicKey\(([0-9]+), ([0-9]+)', public_key)
            if ne:
                n, e = ne[0]
                if n and e:
                    public_key_instance = rsa.PublicKey(int(n), int(e))

        if private_key and public_key:
            return private_key_instance, public_key_instance
        if public_key:
            return public_key_instance
        return private_key_instance


class FernetAdapter(ICipher):
    def new_keys(self, length):
        return Fernet.generate_key().decode('utf8'), False

    def encrypt(self, plain_text, key):
        key = self.str_to_key(key)
        f = Fernet(key[0])
        return f.encrypt(plain_text.encode('utf8')).hex()

    def decrypt(self, cipher_text, key):
        key = self.str_to_key(key)
        f = Fernet(key[0])
        return f.decrypt(bytes.fromhex(cipher_text)).decode('utf8')

    @staticmethod
    def determine_key_length(key):
        return 0

    @staticmethod
    def str_to_key(private_key: str = None, public_key=None):
        private_key = str(hashlib.md5(private_key.encode('utf8')).hexdigest())
        return base64.urlsafe_b64encode(private_key.encode('utf8')), None


class AESAdapter(ICipher):

    def new_keys(self, length):
        random_key = base64.urlsafe_b64encode(os.urandom(32)).decode('utf8')
        return random_key, False

    def encrypt(self, plain_text, key):
        key = self.str_to_key(key)[0]
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        cipher_text, tag = cipher.encrypt_and_digest(plain_text.encode('utf8'))
        nonce, cipher_text, tag = map(lambda element: element.hex(), (nonce, cipher_text, tag))
        return nonce, cipher_text, tag

    def decrypt(self, cipher_text, key):
        key = self.str_to_key(key)[0]
        nonce, cipher_text, tag = re.findall(r"\('([\w]+)', '([\w]+)', '([\w]+)'", cipher_text)[0]
        if not all([nonce, cipher_text, tag]):
            return False
        nonce, cipher_text, tag = map(lambda element: bytes.fromhex(element), (nonce, cipher_text, tag))
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plain_text = cipher.decrypt(cipher_text)
        try:
            cipher.verify(tag)
        except ValueError:
            return "Key incorrect or message corrupted"
        return plain_text.decode('utf8')

    @staticmethod
    def determine_key_length(key):
        return 0

    @staticmethod
    def str_to_key(private_key: str = None, public_key: str=None):
        private_key = str(hashlib.md5(private_key.encode('utf8')).hexdigest())
        return private_key.encode('utf8'), None


class PaillierAdapter(ICipher):

    def new_keys(self, length):
        public_key, private_key = paillier.generate_paillier_keypair(n_length=length)
        private_key, public_key = \
            PaillierPrivateKeyAdaptor(public_key, private_key.p, private_key.q), PaillierPublicKeyAdaptor(public_key.n)
        return private_key, public_key

    def encrypt(self, plain_text, key):
        public_key = self.str_to_key(public_key=key)
        result = ""
        for char in plain_text:
            byte = int.from_bytes(char.encode('utf8'), byteorder='big')
            result += str(public_key.raw_encrypt(byte))+' '
        return result

    def decrypt(self, cipher_text: str, key: str):
        private_key = self.str_to_key(private_key=key)
        if cipher_text[len(cipher_text)-1] != ' ':
            cipher_text += ' '
        block_start, block_end = 0, cipher_text.find(' ')
        result = ""
        while block_end != -1:
            cipher_text_block = int(cipher_text[block_start:block_end])
            plain_text_block = private_key.raw_decrypt(cipher_text_block)
            result += plain_text_block.to_bytes(3, 'big').decode('utf8')
            block_start, block_end = block_end, cipher_text.find(' ', block_end+1)
        return result

    @staticmethod
    def determine_key_length(key):
        if not key:
            return False
        if isinstance(key, paillier.PaillierPublicKey):
            return key.n.bit_length()
        if isinstance(key, paillier.PaillierPrivateKey):
            return key.public_key.n.bit_length()
        return False

    @staticmethod
    def str_to_key(private_key=None, public_key=None):

        private_key_instance = None

        if private_key:

            npq = re.findall(r'PrivateKey\(([0-9]+), ([0-9]+), ([0-9]+)', private_key)
            if npq:
                n, p, q, = npq[0]
                if all([n, p, q]):
                    private_key_instance = PaillierPrivateKeyAdaptor(paillier.PaillierPublicKey(int(n)), p=int(p),
                                                                       q=int(q))

        public_key_instance = None

        if public_key:
            n = re.findall(r'PublicKey\(([0-9]+)', public_key)
            if n:
                n = n[0]
                if n:
                    public_key_instance = PaillierPublicKeyAdaptor(int(n))

        if private_key and public_key:
            return private_key_instance, public_key_instance
        if public_key:
            return public_key_instance
        return private_key_instance


class PaillierPrivateKeyAdaptor(paillier.PaillierPrivateKey):
    def __str__(self):
        return "PrivateKey("+str(self.public_key.n)+", "+str(self.p)+", "+str(self.q)+")"

    def __eq__(self, other):
        if not other:
            return False
        super(paillier.PaillierPrivateKey, self).__eq__(other)


class PaillierPublicKeyAdaptor(paillier.PaillierPublicKey):
    def __str__(self):
        return "PublicKey("+str(self.n)+")"

    def __eq__(self, other):
        if not other:
            return False
        super(paillier.PaillierPublicKey, self).__eq__(other)

