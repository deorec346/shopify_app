# Generated by Django 4.2.7 on 2024-01-24 11:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('connectApp', '0011_shopifydata_sync_flag'),
    ]

    operations = [
        migrations.AlterField(
            model_name='shopifydata',
            name='sync_flag',
            field=models.CharField(default='Pending', max_length=10),
        ),
    ]
