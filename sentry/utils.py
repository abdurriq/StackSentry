import json
import subprocess
import tempfile
import yaml
from typing import Dict, List, Union
import os
from checkov.cloudformation.runner import Runner as CfnRunner
from checkov.cloudformation.context_parser import ContextParser
from checkov.common.output.report import Report
from checkov.common.models.enums import CheckResult

class CloudFormationAnalyser:
    """Analyses CloudFormation templates using cfn-lint for validation and Checkov for security scanning."""

    @staticmethod
    def format_template(content: str) -> str:
        """Format template content as JSON or YAML."""
        try:
            # Try to parse as JSON first
            if content.strip().startswith('{'):
                parsed = json.loads(content)
                return json.dumps(parsed, indent=2)
            else:
                # Parse and dump as YAML for proper formatting
                parsed = yaml.safe_load(content)
                return yaml.dump(parsed, indent=2, default_flow_style=False)
        except Exception as e:
            raise ValueError(f"Failed to format template: {str(e)}")

    @staticmethod
    def _write_temp_template(content: str) -> str:
        """Write template content to a temporary file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
            # Try to parse as JSON first
            try:
                template = json.loads(content)
                yaml.dump(template, tmp)
            except json.JSONDecodeError:
                # If not JSON, assume it's YAML
                tmp.write(content)
            return tmp.name

    @staticmethod
    def _run_cfn_lint(template_path: str) -> List[Dict]:
        """Run cfn-lint on the template."""
        try:
            result = subprocess.run(
                ['cfn-lint', '-f', 'json', template_path],
                capture_output=True,
                text=True,
                check=False
            )

            # cfn-lint outputs to stderr for both errors and warnings
            if result.stderr:
                try:
                    return json.loads(result.stderr)
                except json.JSONDecodeError:
                    print("Raw cfn-lint output:", result.stderr)
                    return [{'Level': 'Error', 'Message': result.stderr}]
            elif result.stdout:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    print("Raw cfn-lint output:", result.stdout)
                    return [{'Level': 'Error', 'Message': result.stdout}]
            return []
        except subprocess.CalledProcessError:
            return [{'Level': 'Error', 'Message': 'Failed to run cfn-lint'}]
        except json.JSONDecodeError:
            return [{'Level': 'Error', 'Message': 'Failed to parse cfn-lint output'}]

    @staticmethod
    def _run_checkov(template_path: str) -> Report:
        """Run Checkov on the template."""
        # Create a temporary directory for the template
        temp_dir = os.path.dirname(template_path)

        # Run Checkov on the template with specific configuration
        runner = CfnRunner()
        # Set external checks directory to None to use only built-in checks
        runner.external_checks_dir = None
        # Disable download of external checks
        runner.download_external_modules = False
        # Run only on the specified file
        report = runner.run(root_folder=None, files=[template_path])
        return report

    @staticmethod
    def _estimate_costs(template_content: str) -> Dict:
        """Estimate costs based on resources in the template."""
        try:
            # Parse template
            try:
                template = json.loads(template_content)
            except json.JSONDecodeError:
                template = yaml.safe_load(template_content)

            # Define hourly cost estimates for common resources
            cost_map = {
                'AWS::EC2::Instance': {
                    't2.micro': 0.0116,  # $8.50/month
                    't2.small': 0.023,   # $17.00/month
                    't3.micro': 0.0104,  # $7.50/month
                    't3.small': 0.0208,  # $15.00/month
                    'm5.large': 0.096,   # $69.00/month
                    'default': 0.069     # $50.00/month
                },
                'AWS::RDS::DBInstance': {
                    'db.t3.micro': 0.018,  # $13.00/month
                    'db.t3.small': 0.036,  # $26.00/month
                    'default': 0.139       # $100.00/month
                },
                'AWS::S3::Bucket': 0.0007,      # $0.50/month base
                'AWS::DynamoDB::Table': 0.035,   # $25.00/month
                'AWS::ElasticLoadBalancingV2::LoadBalancer': 0.025,  # $18.00/month
                'AWS::Lambda::Function': 0.0003   # $0.20/month base
            }

            # Calculate costs for different time periods
            hourly_costs = {}
            resources = template.get('Resources', {})

            for resource_id, resource in resources.items():
                resource_type = resource.get('Type')
                if resource_type in cost_map:
                    if isinstance(cost_map[resource_type], dict):
                        # Get instance type from properties
                        instance_type = resource.get('Properties', {}).get('InstanceType', 'default')
                        hourly = cost_map[resource_type].get(instance_type, cost_map[resource_type]['default'])
                    else:
                        hourly = cost_map[resource_type]

                    service = resource_type.split('::')[1]
                    if service not in hourly_costs:
                        hourly_costs[service] = 0
                    hourly_costs[service] += hourly

            # Calculate costs for different time periods
            hourly_total = sum(hourly_costs.values())
            daily_total = hourly_total * 24
            weekly_total = daily_total * 7
            monthly_total = daily_total * 30
            yearly_total = daily_total * 365

            # Generate 12-month projection with growth
            monthly_projection = []
            growth_factors = {
                'EC2': 1.1,      # 10% monthly growth
                'RDS': 1.15,     # 15% monthly growth
                'S3': 1.2,       # 20% monthly growth
                'DynamoDB': 1.1, # 10% monthly growth
                'Lambda': 1.25,   # 25% monthly growth
                'default': 1.1   # 10% default growth
            }

            current_costs = {
                service: cost * 24 * 30  # Convert hourly to monthly
                for service, cost in hourly_costs.items()
            }

            for month in range(1, 13):
                # Apply growth factors to each service
                projected_costs = {}
                for service, base_cost in current_costs.items():
                    growth = growth_factors.get(service, growth_factors['default'])
                    projected_cost = base_cost * (growth ** (month - 1))
                    projected_costs[service] = projected_cost

                projection = {
                    'month': month,
                    'total': sum(projected_costs.values()),
                    'by_service': projected_costs
                }
                monthly_projection.append(projection)

            return {
                'current': {
                    'hourly_total': hourly_total,
                    'daily_total': daily_total,
                    'weekly_total': weekly_total,
                    'monthly_total': monthly_total,
                    'yearly_total': yearly_total,
                    'by_service': {
                        service: {
                            'hourly': cost,
                            'daily': cost * 24,
                            'weekly': cost * 24 * 7,
                            'monthly': cost * 24 * 30,
                            'yearly': cost * 24 * 365
                        }
                        for service, cost in hourly_costs.items()
                    }
                },
                'projection': monthly_projection
            }
        except Exception as e:
            return {
                'error': str(e),
                'current': {
                    'hourly_total': 0,
                    'daily_total': 0,
                    'weekly_total': 0,
                    'monthly_total': 0,
                    'yearly_total': 0,
                    'by_service': {}
                },
                'projection': []
            }

    def analyse_template(self, template_content: str) -> Dict[str, Union[List, Dict, bool]]:
        """
        Analyse a CloudFormation template using cfn-lint for validation and Checkov for security scanning.

        Returns:
        {
            'security': List of security issues found by Checkov,
            'costs': Cost estimation dictionary,
            'validation': Dictionary with validation results from cfn-lint
        }
        """
        template_path = self._write_temp_template(template_content)

        # Run cfn-lint for validation
        lint_results = self._run_cfn_lint(template_path)
        validation_results = {
            'errors': [],
            'warnings': []
        }

        print("CFN-Lint Results:", json.dumps(lint_results, indent=2))

        # Security-related rule IDs from cfn-lint
        security_rule_ids = {'W2501', 'W2507', 'W2508', 'W2509', 'W2510', 'W2511', 'W2512',
                            'W3005', 'W3006', 'W3007', 'W3008', 'W3009', 'W3010', 'W3011',
                            'W3012', 'W3013', 'W3014', 'W3015', 'W3016', 'W3017', 'W3018',
                            'W3019', 'W3020', 'W3021', 'W3022', 'W3023', 'W3024', 'W3025',
                            'W3026', 'W3027', 'W3028', 'W3029', 'W3030', 'W3031', 'W3032',
                            'W3033', 'W3034', 'W3035', 'W3036', 'W3037', 'W3038', 'W3039',
                            'W3040', 'W3041', 'W3042', 'W3043', 'W3044', 'W3045', 'W3046',
                            'W3047', 'W3048', 'W3049', 'W3050', 'W3051', 'W3052', 'W3053',
                            'W3054', 'W3055', 'W3056', 'W3057', 'W3058', 'W3059', 'W3060',
                            'W3061', 'W3062', 'W3063', 'W3064', 'W3065', 'W3066', 'W3067',
                            'W3068', 'W3069', 'W3070', 'W3071', 'W3072', 'W3073', 'W3074',
                            'W3075', 'W3076', 'W3077', 'W3078', 'W3079', 'W3080', 'W3081',
                            'W3082', 'W3083', 'W3084', 'W3085', 'W3086', 'W3087', 'W3088',
                            'W3089', 'W3090', 'W3091', 'W3092', 'W3093', 'W3094', 'W3095',
                            'W3096', 'W3097', 'W3098', 'W3099', 'W3100', 'W3101', 'W3102',
                            'W3103', 'W3104', 'W3105', 'W3106', 'W3107', 'W3108', 'W3109',
                            'W3110', 'W3111', 'W3112', 'W3113', 'W3114', 'W3115', 'W3116',
                            'W3117', 'W3118', 'W3119', 'W3120', 'W3121', 'W3122', 'W3123',
                            'W3124', 'W3125', 'W3126', 'W3127', 'W3128', 'W3129', 'W3130',
                            'W3131', 'W3132', 'W3133', 'W3134', 'W3135', 'W3136', 'W3137',
                            'W3138', 'W3139', 'W3140', 'W3141', 'W3142', 'W3143', 'W3144',
                            'W3145', 'W3146', 'W3147', 'W3148', 'W3149', 'W3150', 'W3151',
                            'W3152', 'W3153', 'W3154', 'W3155', 'W3156', 'W3157', 'W3158',
                            'W3159', 'W3160', 'W3161', 'W3162', 'W3163', 'W3164', 'W3165',
                            'W3166', 'W3167', 'W3168', 'W3169', 'W3170', 'W3171', 'W3172',
                            'W3173', 'W3174', 'W3175', 'W3176', 'W3177', 'W3178', 'W3179',
                            'W3180', 'W3181', 'W3182', 'W3183', 'W3184', 'W3185', 'W3186',
                            'W3187', 'W3188', 'W3189', 'W3190', 'W3191', 'W3192', 'W3193',
                            'W3194', 'W3195', 'W3196', 'W3197', 'W3198', 'W3199', 'W3200'}

        # Process cfn-lint results
        cfn_lint_security_issues = []
        for result in lint_results:
            rule_id = result.get('Rule', {}).get('Id', 'Unknown')

            # Create validation item
            item = {
                'code': rule_id,
                'message': result.get('Message', ''),
                'location': {
                    'line': result.get('Location', {}).get('Start', {}).get('LineNumber'),
                    'column': result.get('Location', {}).get('Start', {}).get('ColumnNumber')
                },
                'source': 'cfn-lint'  # Indicate that this issue was found by cfn-lint
            }

            # Check if this is a security-related rule
            is_security_rule = rule_id in security_rule_ids or 'security' in result.get('Message', '').lower()

            # Add to appropriate list
            if result.get('Level') == 'Error':
                validation_results['errors'].append(item)

                # If it's a security-related error, also add to security issues
                if is_security_rule:
                    cfn_lint_security_issues.append({
                        'severity': 'HIGH',
                        'title': f'Security Issue: {rule_id}',
                        'description': result.get('Message', ''),
                        'recommendation': 'Fix this security issue to improve your template security.',
                        'source': 'cfn-lint',
                        'location': {
                            'line': result.get('Location', {}).get('Start', {}).get('LineNumber'),
                            'column': result.get('Location', {}).get('Start', {}).get('ColumnNumber')
                        }
                    })
            else:
                validation_results['warnings'].append(item)

                # If it's a security-related warning, also add to security issues
                if is_security_rule:
                    cfn_lint_security_issues.append({
                        'severity': 'MEDIUM',
                        'title': f'Security Issue: {rule_id}',
                        'description': result.get('Message', ''),
                        'recommendation': 'Consider fixing this security warning to improve your template security.',
                        'source': 'cfn-lint',
                        'location': {
                            'line': result.get('Location', {}).get('Start', {}).get('LineNumber'),
                            'column': result.get('Location', {}).get('Start', {}).get('ColumnNumber')
                        }
                    })

        # Run Checkov for security checks
        checkov_report = self._run_checkov(template_path)

        # Print Checkov report details for debugging
        print(f"Checkov Report - Failed Checks: {len(checkov_report.failed_checks)}")
        for i, check in enumerate(checkov_report.failed_checks):
            print(f"Failed Check {i+1}: {check.check_id} - {check.check_name}")

        print(f"Checkov Report - Passed Checks: {len(checkov_report.passed_checks)}")

        # Process security issues
        security_issues = []

        # Process failed checks for security issues
        for record in checkov_report.failed_checks:
            # Extract file path and line number
            file_path = record.file_path
            line_number = record.file_line_range[0] if record.file_line_range else 1

            # All Checkov failed checks are security issues
            # Determine severity based on check ID or name
            severity = 'MEDIUM'  # Default to MEDIUM
            if hasattr(record, 'severity') and record.severity == 'HIGH':
                severity = 'HIGH'
            elif 'high' in record.check_id.lower() or 'critical' in record.check_id.lower():
                severity = 'HIGH'
            elif any(keyword in record.check_name.lower() for keyword in ['encryption', 'public', 'access', 'secure']):
                severity = 'HIGH'

            # Create recommendation based on check name
            recommendation = "No recommendation available"
            if hasattr(record, 'guideline') and record.guideline:
                recommendation = record.guideline
            else:
                # Generate recommendation based on check name
                if 'encryption' in record.check_name.lower():
                    recommendation = "Enable server-side encryption for this resource to protect data at rest."
                elif 'public' in record.check_name.lower():
                    recommendation = "Restrict public access to this resource to improve security."
                elif 'logging' in record.check_name.lower():
                    recommendation = "Enable access logging to track access to this resource."
                elif 'versioning' in record.check_name.lower():
                    recommendation = "Enable versioning to protect against accidental deletion and provide data recovery."

            security_issues.append({
                'severity': severity,
                'title': f'Security Issue: {record.check_id}',
                'description': record.check_name,
                'recommendation': recommendation,
                'source': 'Checkov',  # Indicate that this issue was found by Checkov
                'location': {
                    'line': line_number,
                    'column': 0  # Checkov doesn't provide column information
                }
            })

        # Combine security issues from both tools
        combined_security_issues = security_issues + cfn_lint_security_issues

        # Estimate costs
        cost_estimate = self._estimate_costs(template_content)

        return {
            'security': combined_security_issues,
            'costs': cost_estimate,
            'validation': validation_results
        }

# Create a singleton instance
cfn_analyser = CloudFormationAnalyser()
