from django.urls import path

from Cryptography.apps.main import views

app_name = "main"

urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('cryptography_object/<int:object_id>', views.CryptographyObjectView.as_view(), name='cryptography_object'),
    path('cryptography_object/<int:object_id>/update', views.CryptographyObjectUpdate.as_view(),
         name='cryptography_object_update'),
    path('generate_keys/', views.generate_keys, name='generate_keys'),
    path('cipher_defaults/', views.cipher_defaults, name='cipher_defaults'),
    path('get_user_info/', views.get_user_info, name='get_user_info'),
    path('export_key/<int:object_id>', views.export_key, name='export_key'),
    path('export_key/<int:object_id>/<int:public_key>', views.export_key, name='export_key'),
    path('create_cipher/', views.create_cipher, name='create_cipher')
]