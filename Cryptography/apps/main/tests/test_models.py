from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile

from Cryptography.apps.main import models, adapters, forms


class TestCipher(TestCase):

    def test_engine(self):
        aes = models.Cipher.get_cipher_engine('aEs')
        self.assertIsInstance(aes, adapters.AESAdapter)
        paillier = models.Cipher.get_cipher_engine('PaIlliER')
        self.assertIsInstance(paillier, adapters.PaillierAdapter)
        rsa = models.Cipher.get_cipher_engine('rSa')
        self.assertIsInstance(rsa, adapters.RSAAdapter)
        fernet = models.Cipher.get_cipher_engine('feRnet')
        self.assertIsInstance(fernet, adapters.FernetAdapter)
        none = models.Cipher.get_cipher_engine('non-existing cipher')
        self.assertIs(none, False)


class TestCryptographyObject(TestCase):

    def test_export_to_file(self):
        test_object = models.CryptographyObject()
        test_object.name = 'test'
        response = test_object.export_to_file()
        self.assertEqual(response.status_code, 200)
        response = test_object.export_to_file(public_key=True)
        self.assertEqual(response.status_code, 200)

    def test_validate(self):
        test_object = models.CryptographyObject()
        test_form = forms.CryptographyObjectForm(instance=test_object)
        self.assertIs(test_form.is_valid(), False)

        test_form = forms.CryptographyObjectForm(data={'name': 'test'}, instance=test_object)
        self.assertIs(test_form.is_valid(), True)

        test_object.private_key = '123'
        test_form = forms.CryptographyObjectForm(data={'name': 'test'}, instance=test_object)
        self.assertIs(test_form.is_valid(), False)
        self.assertEqual(len(test_form.errors), 1)

        test_object = models.CryptographyObject()
        test_object.public_key = None
        test_form = forms.CryptographyObjectForm(data={'name': 'test'}, instance=test_object)
        self.assertIs(test_form.is_valid(), False)
        self.assertEqual(len(test_form.errors), 1)

        test_object = models.CryptographyObject(cipher=models.Cipher.objects.filter(is_asymmetric=False).first())
        test_object.public_key = None
        test_form = forms.CryptographyObjectForm(data={'name': 'test'}, instance=test_object)
        self.assertIs(test_form.is_valid(), True)

        test_object.private_key = None
        test_form = forms.CryptographyObjectForm(data={'name': 'test'}, instance=test_object)
        self.assertIs(test_form.is_valid(), False)
        self.assertEqual(len(test_form.errors), 1)

    def test_fingerprint(self):
        test_object = models.CryptographyObject()
        self.assertEqual(len(test_object.fingerprint), 92)

        test_object = models.CryptographyObject(cipher=models.Cipher.objects.filter(is_asymmetric=False).first())
        self.assertEqual(test_object.fingerprint, False)

    def test_file_upload(self):
        file = SimpleUploadedFile("key.pem", b"wrong_key", content_type="application/octet-stream")
        test_form = forms.CryptographyObjectForm(data={'name': 'test'}, files={'private_key': file})
        self.assertEqual(test_form.is_valid(), False)

        valid_key_data = b"-----BEGIN AES PRIVATE KEY-----\n" \
                         b"YlhWNk5TcDJKbnBrWDNZM05tdHVhaVowWGpCcEppVWthSFF4YlQxdExYZz0" \
                         b"=\n-----END AES PRIVATE KEY----- "
        valid_key_file = SimpleUploadedFile("key.pem", valid_key_data, content_type="application/octet-stream")
        test_form = forms.CryptographyObjectForm(data={'name': 'test'}, files={'private_key': valid_key_file})
        self.assertEqual(test_form.is_valid(), True)

        public_key_file_data = b"-----BEGIN PAILLIER PUBLIC KEY-----\n" \
                                b"NTA3NTYyNmM2OTYzNGI2NTc5MjgzMTMwMzIzNzM0MzgzMDM4MzgzMjM4MzMzMTMyMzczOTMxMzEzNzM5MzMzMTM5MzEzMjMwMzgzMzM0MzUzMzMxMzUzMzMyMzczNzMyMzIzMDM5MzIzNjM5MzIzNTMzMzAzNTM0MzkzMTM2MzQzMTMxMzgzNTMxMzIzNTM5MzMzNzMyMzEzNDM2MzUzMzM4MzczNDM4MzYzNTMxMzkzMzM2MzIzODMzMzAzNDM2MzgzMzM4MzEzMzMzMzgzMzM4MzgzNTM3MzYzMDMzMzYzNTMyMzYzOTMzMzYzODMzMzAzNjM2MzEzMjM4MzkzNzM1MzMzNzMxMzQzNTM3MzczMTM5MzEzNzM3MzQzNjMwMzgzMzM2MzMzMTM0MzgzNTMzMzczMjM0MzAzODMxMzEzNTMyMzMzODMxMjk=" \
                                b"\n-----END PAILLIER PUBLIC KEY-----"
        private_key_file_data = b"-----BEGIN PAILLIER PRIVATE KEY-----\n" \
                                b"NTA3MjY5NzY2MTc0NjU0YjY1NzkyODMxMzAzMjM3MzQzODMwMzgzODMyMzgzMzMxMzIzNzM5MzEzMTM3MzkzMzMxMzkzMTMyMzAzODMzMzQzNTMzMzEzNTMzMzIzNzM3MzIzMjMwMzkzMjM2MzkzMjM1MzMzMDM1MzQzOTMxMzYzNDMxMzEzODM1MzEzMjM1MzkzMzM3MzIzMTM0MzYzNTMzMzgzNzM0MzgzNjM1MzEzOTMzMzYzMjM4MzMzMDM0MzYzODMzMzgzMTMzMzMzODMzMzgzODM1MzczNjMwMzMzNjM1MzIzNjM5MzMzNjM4MzMzMDM2MzYzMTMyMzgzOTM3MzUzMzM3MzEzNDM1MzczNzMxMzkzMTM3MzczNDM2MzAzODMzMzYzMzMxMzQzODM1MzMzNzMyMzQzMDM4MzEzMTM1MzIzMzM4MzEyYzIwMzkzNzM5MzkzMzMyMzkzODM2MzYzNDM5MzEzMzM4MzUzMzMxMzYzNTMyMzAzMDMzMzUzOTM0MzgzMjMxMzYzNjMyMzAzNDM1MzAzMjM1MzMzNDMyMzEzOTMyMzgzODM4MzUzMDM1MzQzNDM4MzIzMDM5MzkzNTM1MzMzOTM0MzkzODMyMzEzOTM0MzczODM0MzIzOTMwMzQzMzJjMjAzMTMwMzQzODM1MzIzMTM1MzczOTMzMzYzMzMwMzIzMzMyMzUzODMzMzAzNTM1MzAzMTM1MzIzNjMyMzQzOTMzMzczNjMyMzgzODM0MzUzMTMzMzYzOTM4MzczMDMyMzUzODM2MzczNzM4MzAzMTM2MzUzNTM1MzAzMjM5MzczODMyMzgzMDMyMzczNjM4MzkzNjM5MzUzNTM2MzcyOQ==" \
                                b"\n-----END PAILLIER PRIVATE KEY-----"
        valid_public_key_file = SimpleUploadedFile("public_key.pem", public_key_file_data,
                                             content_type="application/octet-stream")
        valid_private_key_file = SimpleUploadedFile("private_key.pem", private_key_file_data,
                                              content_type="application/octet-stream")
        test_form = forms.CryptographyObjectForm(data={'name': 'test'},
                                                 files={'private_key': valid_private_key_file,
                                                        'public_key': valid_public_key_file})
        self.assertEqual(test_form.is_valid(), True)

        invalid_key_data = b"-----BEGIN AES PRIVATE KEY-----\n" \
                           b"YlhWNk5TcDJKbnBrWDNZM05tdHVhaVowWGpCcEppVWthSFF4YlQxdExYZz0" \
                           b"=\n-----END RSA PRIVATE KEY----- "
        invalid_key_file = SimpleUploadedFile("key.pem", invalid_key_data, content_type="application/octet-stream")
        test_form = forms.CryptographyObjectForm(data={'name': 'test'}, files={'private_key': invalid_key_file})
        self.assertEqual(test_form.is_valid(), False)

        invalid_key_data = b"-----BEGIN AES PRIVAT KEY-----\n" \
                           b"YlhWNk5TcDJKbnBrWDNZM05tdHVhaVowWGpCcEppVWthSFF4YlQxdExYZz0" \
                           b"=\n-----END AES PRIVATE KEY----- "
        invalid_key_file = SimpleUploadedFile("key.pem", invalid_key_data, content_type="application/octet-stream")
        test_form = forms.CryptographyObjectForm(data={'name': 'test'}, files={'private_key': invalid_key_file})
        self.assertEqual(test_form.is_valid(), False)

        invalid_key_data = b"-----BEGIN NON-EXISTING CIPHER PRIVATE KEY-----\n" \
                           b"YlhWNk5TcDJKbnBrWDNZM05tdHVhaVowWGpCcEppVWthSFF4YlQxdExYZz0" \
                           b"=\n-----END NON-EXISTING CIPHER PRIVATE KEY----- "
        invalid_key_file = SimpleUploadedFile("key.pem", invalid_key_data, content_type="application/octet-stream")
        test_form = forms.CryptographyObjectForm(data={'name': 'test'}, files={'private_key': invalid_key_file})
        self.assertEqual(test_form.is_valid(), False)
