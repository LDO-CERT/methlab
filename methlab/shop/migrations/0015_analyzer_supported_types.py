# Generated by Django 3.0.5 on 2020-06-22 15:40

from django.db import migrations, models
import django_better_admin_arrayfield.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('shop', '0014_auto_20200622_1431'),
    ]

    operations = [
        migrations.AddField(
            model_name='analyzer',
            name='supported_types',
            field=django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.CharField(max_length=10), blank=True, null=True, size=None),
        ),
    ]
