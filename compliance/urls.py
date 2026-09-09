from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("healthz/", views.healthz, name="healthz"),
    path("findings/", views.findings_view, name="findings"),
    path("scan/run/", views.run_scan, name="run_scan"),
    path("findings/<str:finding_id>/suppress/", views.toggle_suppression, name="toggle_suppression"),
    path("export/inventory.csv", views.export_inventory_csv, name="export_inventory_csv"),
    path("export/inventory.xlsx", views.export_inventory_xlsx, name="export_inventory_xlsx"),
    path("export/findings.csv", views.export_findings_csv, name="export_findings_csv"),
]
