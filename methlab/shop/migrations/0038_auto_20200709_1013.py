# Generated by Django 3.0.7 on 2020-07-09 08:13

from django.db import migrations
import djgeojson.fields


class Migration(migrations.Migration):

    dependencies = [
        ('shop', '0037_auto_20200707_1530'),
    ]

    operations = [
        migrations.AlterModelManagers(
            name='mail',
            managers=[
            ],
        ),
        migrations.AlterField(
            model_name='mail',
            name='geo_info',
            field=djgeojson.fields.PointField(blank=True, null=True),
        ),
    ]