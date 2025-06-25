import requests
import json
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)

class OllamaHelper:
    """Helper class for Ollama integration with StackSentry."""

    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.api_endpoint = f"{base_url}/api/generate"
        self.model = "llama3:8b"  # Default model

    def set_model(self, model: str) -> None:
        """Set the model to use."""
        self.model = model

    def generate_response(self, prompt: str, system: Optional[str] = None) -> Dict[str, Any]:
        """Generate a response from Ollama."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }

        if system:
            payload["system"] = system

        try:
            response = requests.post(self.api_endpoint, json=payload, timeout=60)
            response.raise_for_status()
            return {
                "success": True,
                "response": response.json()["response"],
                "model": self.model
            }
        except requests.exceptions.ConnectionError:
            logger.error("Failed to connect to Ollama. Is it running?")
            return {
                "success": False,
                "error": "Failed to connect to Ollama. Make sure it's running on this device."
            }
        except Exception as e:
            logger.error(f"Error generating Ollama response: {str(e)}")
            return {
                "success": False,
                "error": f"Error: {str(e)}"
            }

    def list_available_models(self) -> Dict[str, Any]:
        """List available models from Ollama."""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=10)
            response.raise_for_status()
            return {
                "success": True,
                "models": [model["name"] for model in response.json()["models"]]
            }
        except Exception as e:
            logger.error(f"Error listing Ollama models: {str(e)}")
            return {
                "success": False,
                "error": f"Error listing models: {str(e)}"
            }

    def explain_security_issue(self, issue: Dict) -> Dict[str, Any]:
        """Generate a detailed explanation for a security issue."""
        prompt = f"""
        Explain this CloudFormation security issue in detail:

        Title: {issue['title']}
        Severity: {issue['severity']}
        Description: {issue['description']}

        Provide a clear explanation of:
        1. Why this is a security concern
        2. Potential risks if not addressed
        3. Best practices for fixing this issue
        """

        system = "You are a cloud security expert specializing in AWS CloudFormation templates."
        return self.generate_response(prompt, system)

    def suggest_template_fixes(self, template_content: str, validation_errors: List[Dict]) -> Dict[str, Any]:
        """Suggest fixes for template validation errors."""
        errors_text = "\n".join([f"- {e['code']}: {e['message']}" for e in validation_errors])

        prompt = f"""
        Review this CloudFormation template and suggest fixes for the validation errors:

        TEMPLATE:
        ```
        {template_content[:2000]}  # Limit template size to avoid context window issues
        ```

        VALIDATION ERRORS:
        {errors_text}

        Provide specific code suggestions to fix each error.
        """

        system = "You are an AWS CloudFormation expert. Provide accurate and secure fixes for template issues."
        return self.generate_response(prompt, system)

    def optimize_cost(self, template_content: str, cost_estimate: Dict) -> Dict[str, Any]:
        """Suggest cost optimization strategies based on the template."""
        prompt = f"""
        Analyze this CloudFormation template and suggest cost optimization strategies:

        TEMPLATE SUMMARY:
        ```
        {template_content[:1000]}  # Just include the beginning for context
        ```

        CURRENT COST ESTIMATE:
        Monthly Total: ${cost_estimate['current']['monthly_total']}
        Yearly Total: ${cost_estimate['current']['yearly_total']}

        Services:
        {json.dumps(cost_estimate['current']['by_service'], indent=2)}

        Suggest specific changes to optimize costs while maintaining functionality.
        """

        system = "You are a cloud cost optimization expert. Provide practical advice to reduce AWS costs."
        return self.generate_response(prompt, system)

# Create a singleton instance
ollama_helper = OllamaHelper()
