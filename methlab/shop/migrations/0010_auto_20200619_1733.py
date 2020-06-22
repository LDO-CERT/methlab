# Generated by Django 3.0.5 on 2020-06-19 15:33

from django.db import migrations, models
import django_better_admin_arrayfield.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('shop', '0009_auto_20200619_1627'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='ioc',
            name='url',
        ),
        migrations.AddField(
            model_name='ioc',
            name='urls',
            field=django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.CharField(max_length=500), blank=True, null=True, size=None),
        ),
    ]
