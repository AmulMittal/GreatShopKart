# Generated by Django 3.1 on 2021-05-25 06:05

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cart', '0004_cartitem_user'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='cartitem',
            name='user',
        ),
    ]
