import hashlib
import base64
import re
import os

from Crypto.Cipher import AES
from phe import paillier
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

from cryptography.fernet import Fernet


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

    @staticmethod
    def parse_file_data(file_data: str):
        """
        Instructions about how to process file data between header and footer of PEM file.
        In most of cases you shouldn't overload this, but there are situations when you need this.
        :param file_data: base64 encoded data between header and footer of PEM file.
        :return: str: key to set.
        """
        return base64.b64decode(file_data).decode('utf8')

    @staticmethod
    def compose_file_data(key: str):
        """
        Instructions about which information to put between header and footer of PEM file.
        In most of cases you shouldn't overload this, but there are situations when you need this.
        :param key: key to put into PEM file.
        :return: base64 encoded data between header and footer of PEM file.
        """
        return base64.b64encode(key.encode('utf8'))


class RSAAdapter(ICipher):

    def new_keys(self, length):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=length*4,
        )
        private_key_raw = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
        )
        re_object = re.compile(
            b"-----BEGIN RSA PRIVATE KEY-----\n" + b"(.+)" + b"\n-----END RSA PRIVATE KEY-----",
            re.DOTALL)
        private_key = re_object.findall(private_key_raw)[0].decode('utf8')
        public_key_raw = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1,
        )
        re_object = re.compile(
            b"-----BEGIN RSA PUBLIC KEY-----\n" + b"(.+)" + b"\n-----END RSA PUBLIC KEY-----",
            re.DOTALL)
        public_key = re_object.findall(public_key_raw)[0].decode('utf8')
        return private_key, public_key

    def encrypt(self, plain_text, key):
        public_key = self.str_to_key(public_key=key)
        plain_text_bytes = plain_text.encode('utf8')
        result = ""
        for byte in plain_text_bytes:
            byte = bytes([byte])
            result += public_key.encrypt(byte, padding.PKCS1v15()).hex()+' '
        return result

    def decrypt(self, cipher_text, key):
        private_key = self.str_to_key(private_key=key)
        if cipher_text[len(cipher_text) - 1] != ' ':
            cipher_text += ' '
        block_start, block_end = 0, cipher_text.find(' ')
        result = ""
        errors = 0
        plain_block_bytes = ''.encode('utf8')
        while block_end != -1:
            cipher_text_block = bytes.fromhex(cipher_text[block_start:block_end])
            try:
                plain_block_bytes += private_key.decrypt(cipher_text_block, padding.PKCS1v15())
                plain_block = plain_block_bytes.decode(encoding='utf8')
                plain_block_bytes, errors = ''.encode('utf8'), 0
                result += plain_block
            except UnicodeDecodeError as e:
                if errors > 2:
                    raise Exception('Не удалось расшифровать данные.')
                errors += 1
            block_start, block_end = block_end, cipher_text.find(' ', block_end + 1)
        return result

    @staticmethod
    def determine_key_length(key):
        try:
            return key.key_size/4
        except Exception:
            return False

    @staticmethod
    def str_to_key(private_key=None, public_key=None):
        if not private_key and not public_key:
            return False
        private_key_instance = None

        if private_key:
            private_key = b"-----BEGIN RSA PRIVATE KEY-----\n" + private_key.encode('utf8') \
                          + b"\n-----END RSA PRIVATE KEY-----"
            try:
                private_key_instance = serialization.load_pem_private_key(private_key, b'password')
            except Exception as e:
                pass

        public_key_instance = None

        if public_key:
            public_key = b"-----BEGIN RSA PUBLIC KEY-----\n" + public_key.encode('utf8') \
                          + b"\n-----END RSA PUBLIC KEY-----"
            try:
                public_key_instance = serialization.load_pem_public_key(public_key)
            except Exception as e:
                pass

        if private_key and public_key:
            return private_key_instance, public_key_instance
        if public_key:
            return public_key_instance
        return private_key_instance

    @staticmethod
    def parse_file_data(file_data: str):
        return file_data.decode('utf8')

    @staticmethod
    def compose_file_data(key: str):
        return key.encode('utf8')


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
            private_key = bytes.fromhex(private_key).decode('utf8')
            npq = re.findall(r'PrivateKey\(([0-9]+), ([0-9]+), ([0-9]+)', private_key)
            if npq:
                n, p, q, = npq[0]
                if all([n, p, q]):
                    private_key_instance = PaillierPrivateKeyAdaptor(paillier.PaillierPublicKey(int(n)), p=int(p),
                                                                       q=int(q))

        public_key_instance = None

        if public_key:
            public_key = bytes.fromhex(public_key).decode('utf8')
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
        return ("PrivateKey("+str(self.public_key.n)+", "+str(self.p)+", "+str(self.q)+")").encode('utf8').hex()

    def __eq__(self, other):
        if not other:
            return False
        super(paillier.PaillierPrivateKey, self).__eq__(other)


class PaillierPublicKeyAdaptor(paillier.PaillierPublicKey):
    def __str__(self):
        return ("PublicKey("+str(self.n)+")").encode('utf8').hex()

    def __eq__(self, other):
        if not other:
            return False
