# Generated by Django 5.0.7 on 2024-09-09 17:55

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AccessLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('log_id', models.CharField(max_length=255)),
                ('data_hora', models.DateTimeField()),
                ('event', models.CharField(max_length=255)),
                ('device_id', models.CharField(max_length=255)),
            ],
        ),
    ]
