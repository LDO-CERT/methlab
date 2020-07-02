# Generated by Django 3.0.5 on 2020-06-30 13:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('shop', '0023_auto_20200630_1531'),
    ]

    operations = [
        migrations.AlterField(
            model_name='address',
            name='address',
            field=models.EmailField(blank=True, max_length=254, null=True, unique=True),
        ),
        migrations.AlterField(
            model_name='attachment',
            name='md5',
            field=models.CharField(blank=True, max_length=32, null=True, unique=True),
        ),
        migrations.AlterField(
            model_name='attachment',
            name='sha1',
            field=models.CharField(blank=True, max_length=40, null=True, unique=True),
        ),
        migrations.AlterField(
            model_name='attachment',
            name='sha256',
            field=models.CharField(blank=True, max_length=64, null=True, unique=True),
        ),
    ]