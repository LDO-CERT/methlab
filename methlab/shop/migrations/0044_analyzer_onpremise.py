# Generated by Django 3.0.7 on 2020-07-21 09:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('shop', '0043_mail_path'),
    ]

    operations = [
        migrations.AddField(
            model_name='analyzer',
            name='onpremise',
            field=models.BooleanField(default=False),
        ),
    ]