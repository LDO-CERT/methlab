# Generated by Django 3.0.7 on 2020-07-21 10:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('shop', '0045_auto_20200721_1202'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mail',
            name='attachments_path',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='mail',
            name='eml_path',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
    ]
