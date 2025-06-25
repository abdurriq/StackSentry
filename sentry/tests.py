import time

from helium import *
from django.test import TestCase
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.contrib.auth.models import User

from .models import StackTemplate, Analysis
from .views import is_authorised_for_action


class SeleniumTest(StaticLiveServerTestCase):
    def setUp(self):
        password = "test"
        test_user = User.objects.create_user("test_user", password=password)
        self.driver = start_chrome(self.live_server_url)
        self.test_user = test_user

        # Login before running the tests
        click("Login")
        write(test_user.username, into='username')
        write(password, into='password')
        click("Login")

    def tearDown(self):
        kill_browser()

    def check_for_alert_with_message(self, message):
        # Wait for an alert to show, and ensure that the message is what was expected
        wait_until(lambda: Alert())
        self.assertEqual(Alert().text, message)
        time.sleep(1)

    def wait_for_redirect(self):
        # Wait until the page has redirected fully, then return the redirected URL
        wait_until(lambda: self.driver.current_url != self.live_server_url)
        time.sleep(1)
        return self.driver.current_url


class TemplateAnalysisTest(SeleniumTest):
    def setUp(self):
        super().setUp()
        self.test_template = """
        {
            "Resources": {
                "MyBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": "my-test-bucket"
                    }
                }
            }
        }
        """

    def test_template_upload_and_analysis(self):
        # Navigate to template upload page by clicking the + button
        click(S(".btn-outline-light"))

        # Fill in template details
        write("Test Template", into="name")
        write(self.test_template, into="content")

        # Submit the form
        click("Upload & Analyze")

        # Wait for analysis to complete and redirect
        wait_until(lambda: "analysis" in self.driver.current_url)

        # Verify analysis components are present
        self.assertTrue(Text("Security Analysis").exists())
        self.assertTrue(Text("Cost Analysis").exists())
        self.assertTrue(Text("Template Validation").exists())

    def test_template_content_visibility(self):
        # Create template and analysis
        template = StackTemplate.objects.create(
            user=self.test_user,
            name="Test Template",
            content=self.test_template,
            is_analysed=True
        )
        Analysis.objects.create(
            template=template,
            security_issues=[{"severity": "HIGH", "title": "Test Issue", "description": "Test Description"}],
            cost_estimate={"monthly_total": 100, "by_service": {"S3": 100}},
            validation_results={"errors": [], "warnings": []}
        )

        # Navigate to analysis detail page
        go_to(f"{self.live_server_url}/analysis/{template.analysis.id}/")

        # Verify template content is visible
        self.assertTrue(Text("Template Content").exists())
        self.assertTrue(Text("my-test-bucket").exists())  # Content from the template

    def test_analysis_export(self):
        # Create template and analysis
        template = StackTemplate.objects.create(
            user=self.test_user,
            name="Test Template",
            content=self.test_template,
            is_analysed=True
        )
        Analysis.objects.create(
            template=template,
            security_issues=[{"severity": "HIGH", "title": "Test Issue", "description": "Test Description"}],
            cost_estimate={"monthly_total": 100, "by_service": {"S3": 100}},
            validation_results={"errors": [], "warnings": []}
        )

        # Navigate to analysis detail page
        go_to(f"{self.live_server_url}/analysis/{template.analysis.id}/")

        # Click export button
        click("Export Report")

        # Wait for download to start (this will trigger browser's download behavior)
        time.sleep(2)  # Give time for download to initiate

    def test_security_issues_display(self):
        # Create template and analysis with security issues
        template = StackTemplate.objects.create(
            user=self.test_user,
            name="Test Template",
            content=self.test_template,
            is_analysed=True
        )
        Analysis.objects.create(
            template=template,
            security_issues=[
                {"severity": "HIGH", "title": "Insecure S3", "description": "Bucket without encryption"},
                {"severity": "MEDIUM", "title": "Missing Tags", "description": "Resources should have tags"}
            ],
            cost_estimate={"monthly_total": 100, "by_service": {"S3": 100}},
            validation_results={"errors": [], "warnings": []}
        )

        # Navigate to analysis detail page
        go_to(f"{self.live_server_url}/analysis/{template.analysis.id}/")

        # Verify security issues are displayed
        self.assertTrue(Text("High Severity Issues (1)").exists())
        self.assertTrue(Text("Insecure S3").exists())
        self.assertTrue(Text("Medium Severity Issues (1)").exists())
        self.assertTrue(Text("Missing Tags").exists())


class IntegrationTest(TestCase):
    def test_is_authorised_for_action_for_user(self):
        user1 = User.objects.create_user("user1")
        user2 = User.objects.create_user("user2")
        template = StackTemplate.objects.create(
            user=user1,
            name="Test Template",
            content="{}"
        )
        analysis = Analysis.objects.create(
            template=template,
            security_issues=[],
            cost_estimate={"monthly_total": 0, "by_service": {}},
            validation_results={"errors": [], "warnings": []}
        )

        # Only user1 (owner of the template) is authorised for it
        self.assertTrue(is_authorised_for_action(user1, analysis))
        self.assertFalse(is_authorised_for_action(user2, analysis))

    def test_is_authorised_for_action_for_admin(self):
        admin = User.objects.create_user("admin", is_staff=True)
        user1 = User.objects.create_user("user1")
        template = StackTemplate.objects.create(
            user=user1,
            name="Test Template",
            content="{}"
        )
        analysis = Analysis.objects.create(
            template=template,
            security_issues=[],
            cost_estimate={"monthly_total": 0, "by_service": {}},
            validation_results={"errors": [], "warnings": []}
        )

        # Both owner and admin are authorised
        self.assertTrue(is_authorised_for_action(user1, analysis))
        self.assertTrue(is_authorised_for_action(admin, analysis))

        admin_template = StackTemplate.objects.create(
            user=admin,
            name="Admin Template",
            content="{}"
        )
        admin_analysis = Analysis.objects.create(
            template=admin_template,
            security_issues=[],
            cost_estimate={"monthly_total": 0, "by_service": {}},
            validation_results={"errors": [], "warnings": []}
        )

        # Regular user is not authorised for admin's analysis
        self.assertFalse(is_authorised_for_action(user1, admin_analysis))
        self.assertTrue(is_authorised_for_action(admin, admin_analysis))
