# Generated by Django 5.1.5 on 2025-01-25 08:32

import django_ca.modelfields
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='CMCClient',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('certificate', django_ca.modelfields.CertificateField(verbose_name='Client certificate')),
                ('not_before', models.DateTimeField()),
                ('not_after', models.DateTimeField()),
                ('serial', models.CharField(max_length=64, unique=True)),
            ],
        ),
    ]
