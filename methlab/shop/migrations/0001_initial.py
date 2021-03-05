# Generated by Django 3.1.7 on 2021-03-05 12:53

import colorfield.fields
from django.conf import settings
import django.contrib.postgres.indexes
import django.contrib.postgres.search
from django.db import migrations, models
import django.db.models.deletion
import django_better_admin_arrayfield.models.fields
import djgeojson.fields
import taggit.managers


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('contenttypes', '0002_remove_content_type_name'),
    ]

    operations = [
        migrations.CreateModel(
            name='Address',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.CharField(max_length=500), blank=True, null=True, size=None)),
                ('address', models.EmailField(max_length=254, unique=True)),
                ('domain', models.CharField(max_length=500)),
                ('mx_check', models.TextField(blank=True, null=True)),
                ('taxonomy', models.IntegerField(choices=[(0, 'none'), (1, 'info'), (2, 'safe'), (3, 'suspicious'), (4, 'malicious')], default=0)),
            ],
            options={
                'verbose_name_plural': 'addresses',
            },
        ),
        migrations.CreateModel(
            name='Analyzer',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(blank=True, max_length=200, null=True)),
                ('disabled', models.BooleanField(default=False)),
                ('supported_types', django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.CharField(max_length=10), blank=True, null=True, size=None)),
                ('priority', models.PositiveIntegerField(choices=[(1, 'Low'), (2, 'Medium'), (3, 'High')], default=1)),
                ('onpremise', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='Attachment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('binary', models.BooleanField()),
                ('charset', models.CharField(blank=True, max_length=500, null=True)),
                ('content_transfer_encoding', models.CharField(blank=True, max_length=500, null=True)),
                ('content_disposition', models.TextField(blank=True, null=True)),
                ('content_id', models.CharField(blank=True, max_length=500, null=True)),
                ('filename', django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.CharField(max_length=500), blank=True, null=True, size=None)),
                ('filepath', models.CharField(blank=True, max_length=500, null=True)),
                ('mail_content_type', models.CharField(blank=True, max_length=500, null=True)),
                ('md5', models.CharField(blank=True, max_length=32, null=True, unique=True)),
                ('sha1', models.CharField(blank=True, max_length=40, null=True, unique=True)),
                ('sha256', models.CharField(blank=True, max_length=64, null=True, unique=True)),
                ('whitelisted', models.BooleanField(default=False)),
                ('taxonomy', models.IntegerField(choices=[(0, 'none'), (1, 'info'), (2, 'safe'), (3, 'suspicious'), (4, 'malicious')], default=0)),
            ],
        ),
        migrations.CreateModel(
            name='CustomTag',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('object_id', models.IntegerField(db_index=True, verbose_name='object ID')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Domain',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.CharField(max_length=200)),
                ('dig', models.TextField(blank=True, null=True)),
                ('whitelisted', models.BooleanField(default=False)),
                ('taxonomy', models.IntegerField(choices=[(0, 'none'), (1, 'info'), (2, 'safe'), (3, 'suspicious'), (4, 'malicious')], default=0)),
            ],
        ),
        migrations.CreateModel(
            name='Flag',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True, verbose_name='name')),
                ('slug', models.SlugField(max_length=100, unique=True, verbose_name='slug')),
                ('color', colorfield.fields.ColorField(default='#30357B', max_length=18)),
                ('visible', models.BooleanField(default=True)),
            ],
            options={
                'verbose_name': 'Tag',
                'verbose_name_plural': 'Tags',
            },
        ),
        migrations.CreateModel(
            name='InternalInfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('imap_server', models.CharField(max_length=200)),
                ('imap_username', models.CharField(max_length=200)),
                ('imap_password', models.CharField(max_length=200)),
                ('imap_folder', models.CharField(max_length=200)),
                ('cortex_url', models.CharField(max_length=200)),
                ('cortex_api', models.CharField(max_length=200)),
                ('misp_url', models.CharField(blank=True, max_length=200, null=True)),
                ('misp_api', models.CharField(blank=True, max_length=200, null=True)),
                ('vip_list', django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.CharField(max_length=100), blank=True, null=True, size=None)),
                ('vip_domain', models.CharField(max_length=200)),
                ('mimetype_whitelist', django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.CharField(max_length=100), blank=True, null=True, size=None)),
                ('security_emails', django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.EmailField(max_length=254), blank=True, null=True, size=None)),
                ('honeypot_emails', django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.CharField(max_length=200), blank=True, null=True, size=None)),
                ('internal_domains', django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.CharField(max_length=100), blank=True, null=True, size=None)),
                ('http_proxy', models.CharField(blank=True, max_length=200, null=True)),
                ('https_proxy', models.CharField(blank=True, max_length=200, null=True)),
                ('cortex_expiration_days', models.IntegerField(default=30)),
                ('whois_expiration_days', models.IntegerField(default=30)),
            ],
        ),
        migrations.CreateModel(
            name='Ip',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip', models.GenericIPAddressField()),
                ('whitelisted', models.BooleanField(default=False)),
                ('taxonomy', models.IntegerField(choices=[(0, 'none'), (1, 'info'), (2, 'safe'), (3, 'suspicious'), (4, 'malicious')], default=0)),
            ],
        ),
        migrations.CreateModel(
            name='Mail',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('progress', models.PositiveIntegerField(choices=[(0, 'new'), (1, 'processing'), (2, 'done')], default=0)),
                ('official_response', models.PositiveIntegerField(choices=[(0, 'Unknown'), (1, 'SPAM'), (2, 'HAM'), (3, 'Phishing'), (4, 'Social Engineering'), (5, 'Reconnaissance'), (6, 'BlackMail'), (7, 'CEO SCAM'), (10, 'Safe')], default=0)),
                ('submission_date', models.DateTimeField(blank=True, null=True)),
                ('message_id', models.CharField(max_length=1000)),
                ('subject', models.CharField(max_length=1000)),
                ('slug_subject', models.SlugField(default='', editable=False, max_length=1000)),
                ('date', models.DateTimeField(blank=True, null=True)),
                ('received', models.JSONField(blank=True, null=True)),
                ('headers', models.JSONField(blank=True, null=True)),
                ('text_plain', django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.TextField(blank=True, null=True), blank=True, null=True, size=None)),
                ('text_html', django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.TextField(blank=True, null=True), blank=True, null=True, size=None)),
                ('text_not_managed', django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.TextField(blank=True, null=True), blank=True, null=True, size=None)),
                ('sender_ip_address', models.CharField(blank=True, max_length=50, null=True)),
                ('to_domains', django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.CharField(max_length=500), blank=True, null=True, size=None)),
                ('geom', djgeojson.fields.PointField(blank=True, null=True)),
                ('dmark', models.TextField(blank=True, null=True)),
                ('dkim', models.TextField(blank=True, null=True)),
                ('spf', models.TextField(blank=True, null=True)),
                ('arc', models.JSONField(blank=True, null=True)),
                ('eml_path', models.CharField(blank=True, max_length=500, null=True)),
                ('attachments_path', models.CharField(blank=True, max_length=500, null=True)),
                ('taxonomy', models.IntegerField(choices=[(0, 'none'), (1, 'info'), (2, 'safe'), (3, 'suspicious'), (4, 'malicious')], default=0)),
                ('search_vector', django.contrib.postgres.search.SearchVectorField(null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Mail_Addresses',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('field', models.CharField(choices=[('from', 'from'), ('to', 'to'), ('bcc', 'bcc'), ('cc', 'cc'), ('reply_to', 'reply_to')], max_length=10)),
            ],
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('response', models.JSONField(blank=True, null=True)),
                ('object_id', models.PositiveIntegerField()),
                ('taxonomies', django_better_admin_arrayfield.models.fields.ArrayField(base_field=models.CharField(max_length=50), blank=True, null=True, size=None)),
                ('success', models.BooleanField(default=False)),
                ('date', models.DateField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='Url',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.CharField(max_length=2000)),
                ('whitelisted', models.BooleanField(default=False)),
                ('taxonomy', models.IntegerField(choices=[(0, 'none'), (1, 'info'), (2, 'safe'), (3, 'suspicious'), (4, 'malicious')], default=0)),
            ],
        ),
        migrations.CreateModel(
            name='Whitelist',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(max_length=1000)),
                ('type', models.CharField(choices=[('address', 'address'), ('domain', 'domain'), ('url', 'url'), ('ip', 'ip'), ('md5', 'md5'), ('sha256', 'sha256')], max_length=8)),
            ],
        ),
        migrations.CreateModel(
            name='Whois',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('response', models.JSONField(blank=True, null=True)),
                ('date', models.DateField(auto_now_add=True)),
            ],
        ),
        migrations.AddConstraint(
            model_name='whitelist',
            constraint=models.UniqueConstraint(fields=('value', 'type'), name='duplicated_wl'),
        ),
        migrations.AddField(
            model_name='url',
            name='domain',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='shop.domain'),
        ),
        migrations.AddField(
            model_name='url',
            name='tags',
            field=taggit.managers.TaggableManager(blank=True, help_text='A comma-separated list of tags.', through='shop.CustomTag', to='shop.Flag', verbose_name='Tags'),
        ),
        migrations.AddField(
            model_name='report',
            name='analyzer',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='shop.analyzer'),
        ),
        migrations.AddField(
            model_name='report',
            name='content_type',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='contenttypes.contenttype'),
        ),
        migrations.AddField(
            model_name='mail_addresses',
            name='address',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='shop.address'),
        ),
        migrations.AddField(
            model_name='mail_addresses',
            name='mail',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='shop.mail'),
        ),
        migrations.AddField(
            model_name='mail',
            name='addresses',
            field=models.ManyToManyField(related_name='addresses', through='shop.Mail_Addresses', to='shop.Address'),
        ),
        migrations.AddField(
            model_name='mail',
            name='assignee',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='mail',
            name='attachments',
            field=models.ManyToManyField(related_name='attachments', to='shop.Attachment'),
        ),
        migrations.AddField(
            model_name='mail',
            name='ips',
            field=models.ManyToManyField(related_name='ips', to='shop.Ip'),
        ),
        migrations.AddField(
            model_name='mail',
            name='parent',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='shop.mail'),
        ),
        migrations.AddField(
            model_name='mail',
            name='tags',
            field=taggit.managers.TaggableManager(blank=True, help_text='A comma-separated list of tags.', through='shop.CustomTag', to='shop.Flag', verbose_name='Tags'),
        ),
        migrations.AddField(
            model_name='mail',
            name='urls',
            field=models.ManyToManyField(related_name='urls', to='shop.Url'),
        ),
        migrations.AddField(
            model_name='ip',
            name='tags',
            field=taggit.managers.TaggableManager(blank=True, help_text='A comma-separated list of tags.', through='shop.CustomTag', to='shop.Flag', verbose_name='Tags'),
        ),
        migrations.AddField(
            model_name='ip',
            name='whois',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='ip', to='shop.whois'),
        ),
        migrations.AddField(
            model_name='domain',
            name='tags',
            field=taggit.managers.TaggableManager(blank=True, help_text='A comma-separated list of tags.', through='shop.CustomTag', to='shop.Flag', verbose_name='Tags'),
        ),
        migrations.AddField(
            model_name='domain',
            name='whois',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='domain', to='shop.whois'),
        ),
        migrations.AddField(
            model_name='customtag',
            name='content_type',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='shop_customtag_tagged_items', to='contenttypes.contenttype', verbose_name='content type'),
        ),
        migrations.AddField(
            model_name='customtag',
            name='tag',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='shop_customtags', to='shop.flag'),
        ),
        migrations.AddField(
            model_name='attachment',
            name='tags',
            field=taggit.managers.TaggableManager(blank=True, help_text='A comma-separated list of tags.', through='shop.CustomTag', to='shop.Flag', verbose_name='Tags'),
        ),
        migrations.AddField(
            model_name='address',
            name='tags',
            field=taggit.managers.TaggableManager(blank=True, help_text='A comma-separated list of tags.', through='shop.CustomTag', to='shop.Flag', verbose_name='Tags'),
        ),
        migrations.AddIndex(
            model_name='mail',
            index=django.contrib.postgres.indexes.GinIndex(fields=['search_vector'], name='shop_mail_search__5e794b_gin'),
        ),
    ]
