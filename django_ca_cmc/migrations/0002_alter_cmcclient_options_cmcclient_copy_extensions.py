# Generated by Django 5.1.6 on 2025-02-21 18:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('django_ca_cmc', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='cmcclient',
            options={'verbose_name': 'CMC client', 'verbose_name_plural': 'CMC clients'},
        ),
        migrations.AddField(
            model_name='cmcclient',
            name='copy_extensions',
            field=models.BooleanField(default=False, help_text='Copy (almost) all extensions from the CSR if a request is signed by this certificate.'),
        ),
    ]
