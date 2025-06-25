from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
import json

from .helpers.ollama_helper import ollama_helper
from .models import Analysis

@login_required
@require_http_methods(["GET"])
def list_ollama_models(request):
    """List available Ollama models."""
    result = ollama_helper.list_available_models()
    return JsonResponse(result)

@login_required
@require_http_methods(["POST"])
def set_ollama_model(request):
    """Set the Ollama model to use."""
    try:
        data = json.loads(request.body)
        model = data.get('model')
        if not model:
            return JsonResponse({"success": False, "error": "No model specified"}, status=400)

        ollama_helper.set_model(model)
        return JsonResponse({"success": True, "model": model})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=400)

@login_required
@require_http_methods(["POST"])
def analyze_security_issue(request):
    """Generate a detailed explanation for a security issue."""
    try:
        data = json.loads(request.body)
        analysis_id = data.get('analysis_id')
        issue_index = data.get('issue_index', 0)

        if not analysis_id:
            return JsonResponse({"success": False, "error": "No analysis ID specified"}, status=400)

        # Get the analysis and security issues
        analysis = Analysis.objects.get(id=analysis_id, template__user=request.user)
        security_issues = analysis.get_security_issues_by_severity()

        # Get the specified issue
        high_issues = security_issues.get('high', [])
        if not high_issues or issue_index >= len(high_issues):
            return JsonResponse({"success": False, "error": "No security issue found"}, status=404)

        issue = high_issues[issue_index]
        result = ollama_helper.explain_security_issue(issue)
        return JsonResponse(result)
    except Analysis.DoesNotExist:
        return JsonResponse({"success": False, "error": "Analysis not found"}, status=404)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=400)

@login_required
@require_http_methods(["POST"])
def suggest_template_fixes(request):
    """Suggest fixes for template validation errors."""
    try:
        data = json.loads(request.body)
        analysis_id = data.get('analysis_id')

        if not analysis_id:
            return JsonResponse({"success": False, "error": "No analysis ID specified"}, status=400)

        # Get the analysis and validation errors
        analysis = Analysis.objects.get(id=analysis_id, template__user=request.user)
        validation_errors = analysis.get_validation_errors()
        template_content = analysis.get_template_info()['content']

        if not validation_errors:
            return JsonResponse({"success": False, "error": "No validation errors found"}, status=404)

        # Limit to first 3 errors to avoid context window issues
        result = ollama_helper.suggest_template_fixes(template_content, validation_errors[:3])
        return JsonResponse(result)
    except Analysis.DoesNotExist:
        return JsonResponse({"success": False, "error": "Analysis not found"}, status=404)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=400)

@login_required
@require_http_methods(["POST"])
def optimize_cost(request):
    """Suggest cost optimization strategies."""
    try:
        data = json.loads(request.body)
        analysis_id = data.get('analysis_id')

        if not analysis_id:
            return JsonResponse({"success": False, "error": "No analysis ID specified"}, status=400)

        # Get the analysis and cost estimate
        analysis = Analysis.objects.get(id=analysis_id, template__user=request.user)
        cost_estimate = analysis.get_cost_estimate()
        template_content = analysis.get_template_info()['content']

        result = ollama_helper.optimize_cost(template_content, cost_estimate)
        return JsonResponse(result)
    except Analysis.DoesNotExist:
        return JsonResponse({"success": False, "error": "Analysis not found"}, status=404)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=400)
