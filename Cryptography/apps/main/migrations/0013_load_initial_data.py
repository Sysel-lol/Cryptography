from django.db import migrations
from django.core.management import call_command


def forward(apps, schema_editor):
    call_command('loaddata', 'initial_data.json', verbosity=2)


def reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ('main', '0012_remove_cipher_class_name')
    ]

    operations = [
        migrations.RunPython(forward, reverse)
    ]