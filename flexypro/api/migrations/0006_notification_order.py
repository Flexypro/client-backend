# Generated by Django 4.2.7 on 2023-11-30 14:30

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_rename_notification_notification_message'),
    ]

    operations = [
        migrations.AddField(
            model_name='notification',
            name='order',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='api.order'),
        ),
    ]
