# Generated by Django 3.0.5 on 2020-06-24 08:51

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('shop', '0017_auto_20200624_1050'),
    ]

    operations = [
        migrations.AlterField(
            model_name='report',
            name='analyzer',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='shop.Analyzer'),
        ),
    ]
