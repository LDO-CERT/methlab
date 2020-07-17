# Generated by Django 3.0.7 on 2020-07-02 14:00

from django.db import migrations, models
import django_better_admin_arrayfield.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('shop', '0031_auto_20200702_1159'),
    ]

    operations = [
        migrations.AddField(
            model_name='report',
            name='level_worst',
            field=models.PositiveIntegerField(choices=[(0, 'info'), (1, 'safe'), (2, 'suspicious'), (3, 'malicious')], default=0),
        ),
        migrations.AddField(
            model_name='report',
            name='taxonomies',
            field=django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.CharField(max_length=50), blank=True, null=True, size=None),
        ),
    ]