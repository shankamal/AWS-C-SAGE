from django.urls import path
from . import enhanced_views, views

urlpatterns = [
    path("", enhanced_views.dashboard, name="dashboard"),
    path("healthz/", views.healthz, name="healthz"),
    path("findings/", views.findings_view, name="findings"),
    path("inventory/", enhanced_views.inventory_view, name="inventory"),
    path("inventory/<str:resource_key>/", views.resource_detail, name="resource_detail"),
    path("inventory/<str:resource_key>/export.xlsx", views.export_resource_xlsx, name="export_resource_xlsx"),
    path("inventory/<str:resource_key>/export.json", views.export_resource_json, name="export_resource_json"),
    path("scan/run/", views.run_scan, name="run_scan"),
    path("findings/<str:finding_id>/suppress/", views.toggle_suppression, name="toggle_suppression"),
    path("export/inventory.csv", views.export_inventory_csv, name="export_inventory_csv"),
    path("export/inventory.xlsx", enhanced_views.export_inventory_xlsx, name="export_inventory_xlsx"),
    path("export/findings.csv", views.export_findings_csv, name="export_findings_csv"),
]
