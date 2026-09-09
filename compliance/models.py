from django.db import models


class ScanRun(models.Model):
    class Status(models.TextChoices):
        RUNNING = "RUNNING", "Running"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"

    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.RUNNING)
    initiated_by = models.CharField(max_length=150, blank=True)
    account_count = models.PositiveIntegerField(default=0)
    resource_count = models.PositiveIntegerField(default=0)
    compliant_count = models.PositiveIntegerField(default=0)
    non_compliant_count = models.PositiveIntegerField(default=0)
    suppressed_count = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ["-started_at"]


class Finding(models.Model):
    class Status(models.TextChoices):
        COMPLIANT = "COMPLIANT", "Compliant"
        NON_COMPLIANT = "NON_COMPLIANT", "Non-Compliant"
        SUPPRESSED = "SUPPRESSED", "Suppressed"
        ERROR = "ERROR", "Error"

    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="findings")
    finding_key = models.CharField(max_length=64, db_index=True)
    module = models.CharField(max_length=64, db_index=True)
    rule_id = models.CharField(max_length=100, db_index=True)
    account_id = models.CharField(max_length=12, blank=True, db_index=True)
    account_name = models.CharField(max_length=200, blank=True)
    region = models.CharField(max_length=32, blank=True, db_index=True)
    service = models.CharField(max_length=64, blank=True, db_index=True)
    resource_id = models.CharField(max_length=512, blank=True)
    resource_type = models.CharField(max_length=128, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, db_index=True)
    severity = models.CharField(max_length=16, default="MEDIUM")
    title = models.CharField(max_length=255)
    details = models.TextField(blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    detected_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["scan_run", "status"]),
            models.Index(fields=["account_id", "module", "status"]),
        ]
        ordering = ["account_name", "region", "service", "resource_id"]


class ResourceInventory(models.Model):
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="inventory")
    account_id = models.CharField(max_length=12, db_index=True)
    account_name = models.CharField(max_length=200, blank=True)
    region = models.CharField(max_length=32, blank=True, db_index=True)
    service = models.CharField(max_length=64, db_index=True)
    resource_type = models.CharField(max_length=128)
    resource_id = models.CharField(max_length=512)
    resource_arn = models.CharField(max_length=1024, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        indexes = [models.Index(fields=["scan_run", "account_id", "service"])]


class LifecycleRule(models.Model):
    service = models.CharField(max_length=64, db_index=True)
    engine = models.CharField(max_length=100, db_index=True)
    version = models.CharField(max_length=100, db_index=True)
    eol_date = models.DateField()
    source_reference = models.URLField(blank=True)
    notes = models.TextField(blank=True)
    active = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["service", "engine", "version"], name="uniq_lifecycle_rule")]
        ordering = ["service", "engine", "version"]
