# Generated by Django 3.0.5 on 2020-06-30 13:36

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('shop', '0024_auto_20200630_1532'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='attachment',
            name='payload',
        ),
    ]