from django.test import SimpleTestCase
from django.urls import resolve, reverse


class AdminRouteTests(SimpleTestCase):
    def test_canonical_admin_route_resolves(self):
        match = resolve("/admin/")
        self.assertEqual(match.url_name, "csage_admin")
        self.assertEqual(reverse("csage_admin"), "/admin/")

    def test_admin_login_aliases_resolve(self):
        self.assertEqual(resolve("/admin").url_name, "csage_admin_no_slash")
        self.assertEqual(resolve("/admin/login").url_name, "csage_admin_login_no_slash")
        self.assertEqual(resolve("/admin/login/").url_name, "csage_admin_login")

    def test_admin_login_page_is_served_without_application_basic_auth(self):
        for path in ("/admin", "/admin/", "/admin/login", "/admin/login/"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertContains(response, "Administrator Sign In")
