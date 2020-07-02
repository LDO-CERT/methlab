# Generated by Django 3.0.7 on 2020-06-30 15:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('shop', '0029_auto_20200630_1627'),
    ]

    operations = [
        migrations.AddField(
            model_name='address',
            name='domain',
            field=models.CharField(default='a', max_length=500),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='address',
            name='address',
            field=models.EmailField(max_length=254, unique=True),
        ),
    ]