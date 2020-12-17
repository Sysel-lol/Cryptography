from django.db import migrations
from django.core.management import call_command


def forward(apps, schema_editor):
    call_command('loaddata', 'initial_data.json', verbosity=2)


class Migration(migrations.Migration):
    dependencies = [
        ('main', '0008_auto_20201211_1006')
    ]

    operations = [
        migrations.RunPython(forward)
    ]