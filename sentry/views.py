import tempfile

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.core.handlers.wsgi import WSGIRequest
from django.contrib.auth import authenticate, forms, login, logout, mixins
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.generic.edit import DeleteView
from django.template import loader
from django.urls import reverse_lazy
from django.views.generic import CreateView, ListView, DetailView

from .models import StackTemplate, Analysis
from .utils import cfn_analyser
from weasyprint import HTML


@login_required
def format_template(request: WSGIRequest):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    content = request.POST.get('content')
    if not content:
        return JsonResponse({'error': 'No template content provided'}, status=400)

    try:
        formatted_content = cfn_analyser.format_template(content)
        return JsonResponse({'content': formatted_content})
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)


@login_required
def validate_template(request: WSGIRequest):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    content = request.POST.get('content')
    if not content:
        return JsonResponse({'error': 'No template content provided'}, status=400)

    try:
        # Use cfn-lint for validation through our analyser
        analysis_result = cfn_analyser.analyse_template(content)
        return JsonResponse({
            'validation': analysis_result['validation'],
            'isValid': len(analysis_result['validation']['errors']) == 0
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# As per OWASP A01:2021 recommendations for object-level authorisation
# https://owasp.org/Top10/A01_2021-Broken_Access_Control/
def is_authorised_for_action(user, analysis):
    # User is authorised if they are staff, or the owner
    return user.is_staff or analysis.template.user == user


class UploadTemplateView(mixins.LoginRequiredMixin, CreateView):
    model = StackTemplate
    template_name = 'stacktemplate_form.html'
    fields = ['name', 'content']
    success_url = reverse_lazy('analysis_list')

    def form_valid(self, form):
        form.instance.user = self.request.user
        response = super().form_valid(form)

        # Perform analysis using cfn-lint and cfn-guard
        from .utils import cfn_analyser
        analysis_result = cfn_analyser.analyse_template(self.object.content)

        Analysis.objects.create(
            template=self.object,
            security_issues=analysis_result['security'],
            cost_estimate=analysis_result['costs'],
            validation_results=analysis_result['validation']
        )

        # Mark template as analysed
        self.object.is_analysed = True
        self.object.save()

        return response


class AnalysisListView(mixins.LoginRequiredMixin, ListView):
    model = Analysis
    template_name = 'analysis_list.html'
    context_object_name = 'analyses'

    def get_queryset(self):
        if self.request.user.is_staff:
            return Analysis.objects.all()
        return Analysis.objects.filter(template__user=self.request.user)


class AnalysisDeleteView(mixins.LoginRequiredMixin, DeleteView):
    model = Analysis
    success_url = reverse_lazy('analysis_list')

    def get_object(self, queryset=None):
        obj = super().get_object(queryset)
        if not is_authorised_for_action(self.request.user, obj):
            raise PermissionDenied
        return obj

    def delete(self, request, *args, **kwargs):
        """Override delete to also delete the associated template"""
        self.object = self.get_object()
        template = self.object.template
        success_url = self.get_success_url()
        self.object.delete()
        template.delete()
        return redirect(success_url)


class AnalysisDetailView(mixins.LoginRequiredMixin, DetailView):
    model = Analysis
    template_name = 'analysis_detail.html'
    context_object_name = 'analysis'

    def get_object(self, queryset=None):
        # Get the object and verify ownership
        obj = super().get_object(queryset)
        if not is_authorised_for_action(self.request.user, obj):
            raise PermissionDenied
        return obj

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Use model methods to get formatted data
        context['security_issues'] = self.object.get_security_issues_by_severity()
        context['cost_estimate'] = self.object.get_cost_estimate()
        context['validation_errors'] = self.object.get_validation_errors()
        context['validation_warnings'] = self.object.get_validation_warnings()
        context['template_info'] = self.object.get_template_info()

        # Extract template content lines for context
        template_content = context['template_info']['content']
        template_lines = template_content.splitlines()

        # Add line context to validation errors and warnings
        def add_line_context(items):
            for item in items:
                if 'location' in item and item['location'].get('line'):
                    line_num = item['location']['line']

                    # Adjust line number if it's out of bounds
                    if line_num <= 0:
                        line_num = 1
                    elif line_num > len(template_lines):
                        line_num = len(template_lines)

                    # Get a few lines before and after for context
                    start_line = max(0, line_num - 3)
                    end_line = min(len(template_lines), line_num + 2)

                    # Extract the relevant lines with line numbers
                    context_lines = []
                    for i in range(start_line, end_line):
                        context_lines.append({
                            'number': i + 1,  # Line numbers are 1-based
                            'content': template_lines[i],
                            'is_error_line': i + 1 == line_num
                        })

                    item['context_lines'] = context_lines

                    # Update the line number in the location to match what we're displaying
                    item['location']['line'] = line_num

        add_line_context(context['validation_errors'])
        add_line_context(context['validation_warnings'])

        # Convert cost projection data to JSON for the chart if it exists
        import json
        if 'projection' in context['cost_estimate']:
            context['cost_estimate']['projection'] = json.dumps(context['cost_estimate']['projection'])

        return context


def index(request: WSGIRequest):
    if request.user.is_authenticated:
        return redirect("analysis_list")
    return render(request, "index.html")


def register(request: WSGIRequest):
    if request.method == "POST":
        form = forms.UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=raw_password)
            login(request, user)
            return redirect(settings.LOGIN_REDIRECT_URL)
    else:
        form = forms.UserCreationForm()
    return render(request, "registration/register.html", {'form': form})


def logout_redirect(request: WSGIRequest):
    logout(request)
    return redirect("index")


@login_required
def export_analysis(request: WSGIRequest, pk: int):
    analysis = get_object_or_404(Analysis, id=pk, template__user=request.user)

    # Prepare context data using model methods
    context = {
        'analysis': analysis,
        'template_info': analysis.get_template_info(),
        'security_issues': analysis.get_security_issues_by_severity(),
        'cost_estimate': analysis.get_cost_estimate(),
        'validation_errors': analysis.get_validation_errors(),
        'validation_warnings': analysis.get_validation_warnings()
    }

    # Extract template content lines for context
    template_content = context['template_info']['content']
    template_lines = template_content.splitlines()

    # Add line context to validation errors and warnings
    def add_line_context(items):
        for item in items:
            if 'location' in item and item['location'].get('line'):
                line_num = item['location']['line']

                # Adjust line number if it's out of bounds
                if line_num <= 0:
                    line_num = 1
                elif line_num > len(template_lines):
                    line_num = len(template_lines)

                # Get a few lines before and after for context
                start_line = max(0, line_num - 3)
                end_line = min(len(template_lines), line_num + 2)

                # Extract the relevant lines with line numbers
                context_lines = []
                for i in range(start_line, end_line):
                    line_marker = '→ ' if i + 1 == line_num else '  '
                    context_lines.append({
                        'number': i + 1,  # Line numbers are 1-based
                        'content': template_lines[i],
                        'is_error_line': i + 1 == line_num
                    })

                item['context_lines'] = context_lines

                # Update the line number in the location to match what we're displaying
                item['location']['line'] = line_num

    add_line_context(context['validation_errors'])
    add_line_context(context['validation_warnings'])

    # Generate chart image for the PDF
    import matplotlib.pyplot as plt
    import matplotlib
    import base64
    import io
    from matplotlib.colors import LinearSegmentedColormap

    # Use Agg backend for non-interactive plotting
    matplotlib.use('Agg')

    # Get projection data
    if 'projection' in context['cost_estimate']:
        projection_data = context['cost_estimate']['projection']
    else:
        # Create default projection data if not available
        monthly_total = context['cost_estimate'].get('monthly_total', 0)
        projection_data = [
            {
                'month': i,
                'total': monthly_total,
                'by_service': {'Total': monthly_total}
            }
            for i in range(1, 13)
        ]

    # Create figure and axis
    plt.figure(figsize=(10, 6))

    # Define colors for different services
    colors = ['#2563eb', '#dc2626', '#059669', '#d97706', '#7c3aed', '#db2777', '#2dd4bf', '#84cc16']

    # Get all services from the first month's data
    services = list(projection_data[0]['by_service'].keys())

    # Create x-axis labels (months)
    months = [f"Month {d['month']}" for d in projection_data]

    # Plot each service as a line
    for i, service in enumerate(services):
        values = [d['by_service'][service] for d in projection_data]
        plt.plot(months, values, marker='o', linewidth=2, label=service, color=colors[i % len(colors)])

    # Add labels and title
    plt.xlabel('Month')
    plt.ylabel('Cost ($)')
    plt.title('Monthly Cost Projection by Service')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.xticks(rotation=45)

    # Add legend
    plt.legend(loc='upper left', bbox_to_anchor=(1, 1))

    # Adjust layout to make room for the legend
    plt.tight_layout()

    # Save the chart to a base64 encoded string
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=100)
    buffer.seek(0)
    chart_image = base64.b64encode(buffer.getvalue()).decode('utf-8')
    plt.close()

    # Add the chart image to the context
    context['chart_image'] = chart_image

    # Convert cost projection data to JSON for the template if it exists
    import json
    if 'projection' in context['cost_estimate']:
        context['cost_estimate']['projection'] = json.dumps(context['cost_estimate']['projection'])

    # Render the analysis detail template to a string
    html_string = loader.render_to_string('analysis_export.html', context)

    # Create a temporary file to store the PDF
    with tempfile.NamedTemporaryFile(delete=True) as output:
        # Generate PDF from the HTML string
        HTML(string=html_string).write_pdf(output)

        # Reset file pointer
        output.seek(0)

        # Create the HTTP response with PDF content
        response = HttpResponse(output.read(), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="analysis_{analysis.id}.pdf"'

    return response
