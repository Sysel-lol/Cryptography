# Generated by Django 3.1.4 on 2020-12-09 07:38

import Cryptography.apps.main.models
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0003_auto_20201209_1016'),
    ]

    operations = [
        migrations.AddField(
            model_name='asymmetriccryptographyobject',
            name='key_length',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.DO_NOTHING, to='main.cipherkeylengthrelation'),
        ),
        migrations.AddField(
            model_name='symmetriccryptographyobject',
            name='key_length',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.DO_NOTHING, to='main.cipherkeylengthrelation'),
        ),
        migrations.AlterField(
            model_name='cipherkeylength',
            name='length',
            field=models.SmallIntegerField(choices=[(0, 'Любая'), (64, '64'), (128, '128'), (256, '256'), (512, '512')], verbose_name='Длинна ключа'),
        ),
    ]