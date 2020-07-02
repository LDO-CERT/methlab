# Generated by Django 3.0.7 on 2020-07-02 14:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('shop', '0032_auto_20200702_1600'),
    ]

    operations = [
        migrations.AlterField(
            model_name='report',
            name='level_worst',
            field=models.PositiveIntegerField(choices=[(0, 'none'), (1, 'info'), (2, 'safe'), (3, 'suspicious'), (4, 'malicious')], default=0),
        ),
    ]
