from django.core.exceptions import ValidationError
from django.db import models
from django.contrib.auth.models import User
import json


def validate_security_issues(value):
    if not isinstance(value, list):
        raise ValidationError('Security issues must be a list')

    required_fields = {'severity', 'title', 'description'}
    valid_severities = {'HIGH', 'MEDIUM', 'LOW'}

    for issue in value:
        if not isinstance(issue, dict):
            raise ValidationError('Each security issue must be an object')

        # Check required fields
        if not all(field in issue for field in required_fields):
            raise ValidationError(f'Security issue missing required fields: {required_fields}')

        # Validate severity
        if issue['severity'] not in valid_severities:
            raise ValidationError(f'Invalid severity level: {issue["severity"]}')


def validate_cost_estimate(value):
    # Handle legacy format (simple number)
    if isinstance(value, (int, float)):
        return

    if not isinstance(value, dict):
        raise ValidationError('Cost estimate must be an object or number')

    required_fields = {'monthly_total', 'by_service'}
    if not all(field in value for field in required_fields):
        raise ValidationError(f'Cost estimate missing required fields: {required_fields}')

    if not isinstance(value['monthly_total'], (int, float)):
        raise ValidationError('Monthly total must be a number')

    if not isinstance(value['by_service'], dict):
        raise ValidationError('Service costs must be an object')

    for cost in value['by_service'].values():
        if not isinstance(cost, (int, float)):
            raise ValidationError('Service cost must be a number')


def validate_validation_results(value):
    # Handle legacy format (boolean)
    if isinstance(value, bool):
        return

    if not isinstance(value, dict):
        raise ValidationError('Validation results must be an object or boolean')

    required_fields = {'errors', 'warnings'}
    if not all(field in value for field in required_fields):
        raise ValidationError(f'Validation results missing required fields: {required_fields}')

    if not isinstance(value['errors'], list):
        raise ValidationError('Errors must be a list')

    if not isinstance(value['warnings'], list):
        raise ValidationError('Warnings must be a list')

    for item in value['errors'] + value['warnings']:
        if not isinstance(item, dict):
            raise ValidationError('Each validation item must be an object')
        if 'code' not in item or 'message' not in item:
            raise ValidationError('Validation items must have code and message fields')


class StackTemplate(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    content = models.TextField()
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_analysed = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if self.pk:  # If this is an update
            # Prevent content modification after initial save
            orig = StackTemplate.objects.get(pk=self.pk)
            if orig.content != self.content:
                raise ValidationError("Template content cannot be modified after creation")
        super().save(*args, **kwargs)


class Analysis(models.Model):
    template = models.OneToOneField(StackTemplate, on_delete=models.CASCADE)
    security_issues = models.JSONField(validators=[validate_security_issues])
    cost_estimate = models.JSONField(validators=[validate_cost_estimate])
    validation_results = models.JSONField(validators=[validate_validation_results])
    analysed_at = models.DateTimeField(auto_now_add=True)

    def get_security_issues_by_severity(self):
        """Group security issues by severity level."""
        issues = {
            'high': [],
            'medium': [],
            'low': []
        }
        for issue in self.security_issues:
            severity = issue['severity'].lower()
            if severity in issues:
                issues[severity].append(issue)
        return issues

    def get_cost_estimate(self):
        """Get the complete cost estimate data."""
        if isinstance(self.cost_estimate, (int, float)):
            # Handle legacy format
            hourly = float(self.cost_estimate) / (24 * 30)  # Convert monthly to hourly
            return {
                'current': {
                    'hourly_total': hourly,
                    'daily_total': hourly * 24,
                    'weekly_total': hourly * 24 * 7,
                    'monthly_total': float(self.cost_estimate),
                    'yearly_total': float(self.cost_estimate) * 12,
                    'by_service': {
                        'Total': {
                            'hourly': hourly,
                            'daily': hourly * 24,
                            'weekly': hourly * 24 * 7,
                            'monthly': float(self.cost_estimate),
                            'yearly': float(self.cost_estimate) * 12
                        }
                    }
                },
                'projection': [
                    {
                        'month': i,
                        'total': float(self.cost_estimate),
                        'by_service': {'Total': float(self.cost_estimate)}
                    }
                    for i in range(1, 13)
                ]
            }
        return self.cost_estimate

    def get_validation_errors(self):
        """Get validation errors."""
        if isinstance(self.validation_results, bool):
            return []
        return self.validation_results.get('errors', [])

    def get_validation_warnings(self):
        """Get validation warnings."""
        if isinstance(self.validation_results, bool):
            return []
        return self.validation_results.get('warnings', [])

    def get_template_info(self):
        """Get template metadata and content."""
        return {
            'name': self.template.name,
            'uploaded_at': self.template.uploaded_at,
            'analysed_at': self.analysed_at,
            'content': self.template.content,
        }
