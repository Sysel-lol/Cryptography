from django.test import TestCase
from django.shortcuts import reverse
from django.http import HttpResponse, JsonResponse, HttpResponseNotFound

from Cryptography.apps.main import models


class TestViews(TestCase):

    def test_index_page(self):
        response = self.client.get('http://127.0.0.1:8000')
        self.assertEqual(response.status_code, 200)

    def test_cryptography_object_page(self):
        sample_object = models.CryptographyObject(name='test')
        sample_object.save()
        response = self.client.get('http://127.0.0.1:8000'+reverse('main:cryptography_object',
                                                                   kwargs={'object_id': sample_object.id}))
        self.assertEqual(response.status_code, 200)

        response = self.client.get('http://127.0.0.1:8000'+reverse('main:cryptography_object',
                                                                   kwargs={'object_id': 99}))
        self.assertEqual(response.status_code, 404)

    def test_export_key(self):
        sample_object = models.CryptographyObject(name='test')
        sample_object.save()
        response = self.client.get('http://127.0.0.1:8000' + reverse('main:export_key',
                                                                     kwargs={'object_id': sample_object.id}))
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.status_code, 200)

        response = self.client.get('http://127.0.0.1:8000' + reverse('main:export_key',
                                                                     kwargs={'object_id': sample_object.id,
                                                                             'public_key': 1}))
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.status_code, 200)

    def test_generate_keys(self):
        test_object = models.CipherKeyLengthRelation.objects.first()
        response = self.client.get(reverse('main:generate_keys'), {'object_id': test_object.id},
                                    content_type='application/json',
                                    HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertIsInstance(response, JsonResponse)

        response = self.client.get(reverse('main:generate_keys'), {'cipher_key_length_relation_id': -1},
                                   content_type='application/json',
                                   HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertIsInstance(response, HttpResponseNotFound)

    def test_cipher_defaults(self):
        test_object = models.Cipher.objects.first()
        response = self.client.get(reverse('main:cipher_defaults'), {'cipher_id': test_object.id},
                                    content_type='application/json',
                                    HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertIsInstance(response, JsonResponse)

        response = self.client.get(reverse('main:cipher_defaults'), {'cipher_id': -1},
                                   content_type='application/json',
                                   HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertIsInstance(response, HttpResponseNotFound)

    def test_get_user_info(self):
        response = self.client.get(reverse('main:get_user_info'),
                                    content_type='application/json',
                                    HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.status_code, 200)