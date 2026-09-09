from django.contrib import admin
from .models import Finding, LifecycleRule, ResourceInventory, ScanRun

@admin.register(ScanRun)
class ScanRunAdmin(admin.ModelAdmin):
    list_display = ("id", "started_at", "completed_at", "status", "account_count", "resource_count", "non_compliant_count", "suppressed_count")
    list_filter = ("status",)

@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("rule_id", "account_name", "region", "service", "resource_id", "status", "severity")
    list_filter = ("status", "severity", "module", "service")
    search_fields = ("finding_key", "rule_id", "account_id", "account_name", "resource_id", "title")

@admin.register(ResourceInventory)
class ResourceInventoryAdmin(admin.ModelAdmin):
    list_display = ("account_name", "region", "service", "resource_type", "resource_id")
    list_filter = ("service", "region")
    search_fields = ("account_id", "account_name", "resource_id", "resource_arn")

@admin.register(LifecycleRule)
class LifecycleRuleAdmin(admin.ModelAdmin):
    list_display = ("service", "engine", "version", "eol_date", "active", "updated_at")
    list_filter = ("service", "active")
    search_fields = ("engine", "version")
