# Generated for C-SAGE
from django.db import migrations, models
import django.db.models.deletion

class Migration(migrations.Migration):
    initial = True
    dependencies = []
    operations = [
        migrations.CreateModel(
            name="LifecycleRule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("service", models.CharField(db_index=True, max_length=64)),
                ("engine", models.CharField(db_index=True, max_length=100)),
                ("version", models.CharField(db_index=True, max_length=100)),
                ("eol_date", models.DateField()),
                ("source_reference", models.URLField(blank=True)),
                ("notes", models.TextField(blank=True)),
                ("active", models.BooleanField(default=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["service", "engine", "version"]},
        ),
        migrations.CreateModel(
            name="ScanRun",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("started_at", models.DateTimeField(auto_now_add=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("status", models.CharField(choices=[("RUNNING", "Running"), ("COMPLETED", "Completed"), ("FAILED", "Failed")], default="RUNNING", max_length=16)),
                ("initiated_by", models.CharField(blank=True, max_length=150)),
                ("account_count", models.PositiveIntegerField(default=0)),
                ("resource_count", models.PositiveIntegerField(default=0)),
                ("compliant_count", models.PositiveIntegerField(default=0)),
                ("non_compliant_count", models.PositiveIntegerField(default=0)),
                ("suppressed_count", models.PositiveIntegerField(default=0)),
                ("error_message", models.TextField(blank=True)),
            ],
            options={"ordering": ["-started_at"]},
        ),
        migrations.CreateModel(
            name="ResourceInventory",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("account_id", models.CharField(db_index=True, max_length=12)),
                ("account_name", models.CharField(blank=True, max_length=200)),
                ("region", models.CharField(blank=True, db_index=True, max_length=32)),
                ("service", models.CharField(db_index=True, max_length=64)),
                ("resource_type", models.CharField(max_length=128)),
                ("resource_id", models.CharField(max_length=512)),
                ("resource_arn", models.CharField(blank=True, max_length=1024)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("scan_run", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="inventory", to="compliance.scanrun")),
            ],
        ),
        migrations.CreateModel(
            name="Finding",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("finding_key", models.CharField(db_index=True, max_length=64)),
                ("module", models.CharField(db_index=True, max_length=64)),
                ("rule_id", models.CharField(db_index=True, max_length=100)),
                ("account_id", models.CharField(blank=True, db_index=True, max_length=12)),
                ("account_name", models.CharField(blank=True, max_length=200)),
                ("region", models.CharField(blank=True, db_index=True, max_length=32)),
                ("service", models.CharField(blank=True, db_index=True, max_length=64)),
                ("resource_id", models.CharField(blank=True, max_length=512)),
                ("resource_type", models.CharField(blank=True, max_length=128)),
                ("status", models.CharField(choices=[("COMPLIANT", "Compliant"), ("NON_COMPLIANT", "Non-Compliant"), ("SUPPRESSED", "Suppressed"), ("ERROR", "Error")], db_index=True, max_length=20)),
                ("severity", models.CharField(default="MEDIUM", max_length=16)),
                ("title", models.CharField(max_length=255)),
                ("details", models.TextField(blank=True)),
                ("evidence", models.JSONField(blank=True, default=dict)),
                ("detected_at", models.DateTimeField(auto_now_add=True)),
                ("scan_run", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="findings", to="compliance.scanrun")),
            ],
            options={"ordering": ["account_name", "region", "service", "resource_id"]},
        ),
        migrations.AddConstraint(model_name="lifecyclerule", constraint=models.UniqueConstraint(fields=("service", "engine", "version"), name="uniq_lifecycle_rule")),
        migrations.AddIndex(model_name="resourceinventory", index=models.Index(fields=["scan_run", "account_id", "service"], name="compliance__scan_ru_3b3e08_idx")),
        migrations.AddIndex(model_name="finding", index=models.Index(fields=["scan_run", "status"], name="compliance__scan_ru_344003_idx")),
        migrations.AddIndex(model_name="finding", index=models.Index(fields=["account_id", "module", "status"], name="compliance__account_38d822_idx")),
    ]
