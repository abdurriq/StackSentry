import json
import unittest
from unittest.mock import patch, MagicMock
import yaml
import tempfile
import os

from .utils import CloudFormationAnalyser


class TestCloudFormationAnalyser(unittest.TestCase):
    """Tests for the CloudFormationAnalyser class"""

    def setUp(self):
        self.analyser = CloudFormationAnalyser()
        self.json_template = """
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
        self.yaml_template = """
        Resources:
          MyBucket:
            Type: AWS::S3::Bucket
            Properties:
              BucketName: my-test-bucket
        """

    def test_format_template_json(self):
        """Test formatting a JSON template"""
        formatted = self.analyser.format_template(self.json_template)
        # Verify it's valid JSON
        parsed = json.loads(formatted)
        self.assertEqual(parsed["Resources"]["MyBucket"]["Type"], "AWS::S3::Bucket")
        self.assertEqual(parsed["Resources"]["MyBucket"]["Properties"]["BucketName"], "my-test-bucket")

    def test_format_template_yaml(self):
        """Test formatting a YAML template"""
        formatted = self.analyser.format_template(self.yaml_template)
        # Verify it's valid YAML
        parsed = yaml.safe_load(formatted)
        self.assertEqual(parsed["Resources"]["MyBucket"]["Type"], "AWS::S3::Bucket")
        self.assertEqual(parsed["Resources"]["MyBucket"]["Properties"]["BucketName"], "my-test-bucket")

    def test_format_template_invalid(self):
        """Test formatting an invalid template"""
        invalid_template = "{ This is not valid JSON or YAML }"
        with self.assertRaises(ValueError):
            self.analyser.format_template(invalid_template)

    def test_write_temp_template_json(self):
        """Test writing a JSON template to a temporary file"""
        temp_path = self.analyser._write_temp_template(self.json_template)
        try:
            self.assertTrue(os.path.exists(temp_path))
            with open(temp_path, 'r') as f:
                content = f.read()
            # Verify the content was written correctly
            parsed = yaml.safe_load(content)
            self.assertEqual(parsed["Resources"]["MyBucket"]["Type"], "AWS::S3::Bucket")
        finally:
            # Clean up
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_write_temp_template_yaml(self):
        """Test writing a YAML template to a temporary file"""
        temp_path = self.analyser._write_temp_template(self.yaml_template)
        try:
            self.assertTrue(os.path.exists(temp_path))
            with open(temp_path, 'r') as f:
                content = f.read()
            # Verify the content was written correctly
            parsed = yaml.safe_load(content)
            self.assertEqual(parsed["Resources"]["MyBucket"]["Type"], "AWS::S3::Bucket")
        finally:
            # Clean up
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    @patch('subprocess.run')
    def test_run_cfn_lint_success(self, mock_run):
        """Test running cfn-lint with successful output"""
        # Mock subprocess.run to return successful output
        mock_process = MagicMock()
        mock_process.stderr = '[]'
        mock_process.stdout = ''
        mock_run.return_value = mock_process

        result = self.analyser._run_cfn_lint('dummy_path')
        self.assertEqual(result, [])
        mock_run.assert_called_once()

    @patch('subprocess.run')
    def test_run_cfn_lint_with_errors(self, mock_run):
        """Test running cfn-lint with errors"""
        # Mock subprocess.run to return error output
        mock_process = MagicMock()
        mock_process.stderr = '[{"Level": "Error", "Message": "Test error"}]'
        mock_process.stdout = ''
        mock_run.return_value = mock_process

        result = self.analyser._run_cfn_lint('dummy_path')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['Level'], 'Error')
        self.assertEqual(result[0]['Message'], 'Test error')
        mock_run.assert_called_once()

    def test_estimate_costs_json(self):
        """Test cost estimation with a JSON template"""
        costs = self.analyser._estimate_costs(self.json_template)

        # Verify the structure of the cost estimate
        self.assertIn('current', costs)
        self.assertIn('hourly_total', costs['current'])
        self.assertIn('monthly_total', costs['current'])
        self.assertIn('by_service', costs['current'])
        self.assertIn('projection', costs)

        # Verify S3 costs are included
        self.assertIn('S3', costs['current']['by_service'])

        # Verify projection has 12 months
        self.assertEqual(len(costs['projection']), 12)

    def test_estimate_costs_yaml(self):
        """Test cost estimation with a YAML template"""
        costs = self.analyser._estimate_costs(self.yaml_template)

        # Verify the structure of the cost estimate
        self.assertIn('current', costs)
        self.assertIn('hourly_total', costs['current'])
        self.assertIn('monthly_total', costs['current'])
        self.assertIn('by_service', costs['current'])
        self.assertIn('projection', costs)

        # Verify S3 costs are included
        self.assertIn('S3', costs['current']['by_service'])

        # Verify projection has 12 months
        self.assertEqual(len(costs['projection']), 12)

    def test_estimate_costs_with_multiple_resources(self):
        """Test cost estimation with multiple resources"""
        template = """
        {
            "Resources": {
                "MyBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": "my-test-bucket"
                    }
                },
                "MyInstance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "InstanceType": "t2.micro"
                    }
                },
                "MyDatabase": {
                    "Type": "AWS::RDS::DBInstance",
                    "Properties": {
                        "DBInstanceClass": "db.t3.micro"
                    }
                }
            }
        }
        """

        costs = self.analyser._estimate_costs(template)

        # Verify all services are included
        self.assertIn('S3', costs['current']['by_service'])
        self.assertIn('EC2', costs['current']['by_service'])
        self.assertIn('RDS', costs['current']['by_service'])

        # Verify services are included in the cost calculation
        # Note: We don't test exact values as they might change in the implementation
        self.assertGreater(costs['current']['hourly_total'], 0)
        self.assertGreater(costs['current']['monthly_total'], 0)

        # Verify individual service costs
        self.assertGreater(costs['current']['by_service']['S3']['hourly'], 0)
        self.assertGreater(costs['current']['by_service']['EC2']['hourly'], 0)
        self.assertGreater(costs['current']['by_service']['RDS']['hourly'], 0)

    @patch('subprocess.run')
    @patch.object(CloudFormationAnalyser, '_run_checkov')
    def test_analyse_template_integration(self, mock_run_checkov, mock_run):
        """Test the full template analysis process"""
        # Mock subprocess.run for cfn-lint
        mock_process = MagicMock()
        mock_process.stderr = '[]'
        mock_process.stdout = ''
        mock_run.return_value = mock_process

        # Mock Checkov report
        mock_report = MagicMock()
        mock_report.failed_checks = []
        mock_report.passed_checks = []
        mock_run_checkov.return_value = mock_report

        # Run analysis
        result = self.analyser.analyse_template(self.json_template)

        # Verify the structure of the result
        self.assertIn('security', result)
        self.assertIn('costs', result)
        self.assertIn('validation', result)

        # Verify validation results
        self.assertIn('errors', result['validation'])
        self.assertIn('warnings', result['validation'])

        # Verify cost estimate
        self.assertIn('current', result['costs'])
        self.assertIn('projection', result['costs'])

        # Verify security issues
        self.assertEqual(type(result['security']), list)

    def test_analyse_template_with_invalid_template(self):
        """Test analysis with an invalid template"""
        invalid_template = "{ This is not valid JSON or YAML }"

        # We expect the analysis to handle the error gracefully
        with patch('builtins.print'):  # Suppress print statements
            result = self.analyser.analyse_template(invalid_template)

        # Verify the structure of the result
        self.assertIn('security', result)
        self.assertIn('costs', result)
        self.assertIn('validation', result)

        # Verify validation results contain errors
        self.assertTrue(len(result['validation']['errors']) > 0)
