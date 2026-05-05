from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("servers", "0002_server_codebase_paths"),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="host_key_algorithm",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="server",
            name="host_key_fingerprint",
            field=models.CharField(blank=True, max_length=255),
        ),
    ]