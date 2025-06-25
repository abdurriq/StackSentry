"""
URL configuration for stack_sentry project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path

from sentry.views import index, register, logout_redirect, export_analysis
from sentry import views
from sentry import api_views

urlpatterns = [
    path("", index, name="index"),
    path("accounts/register/", register, name="register"),
    path("accounts/logout/", logout_redirect, name="logout"),  # NOTE: Overrides default logout view
    path("accounts/", include("django.contrib.auth.urls")),
    path("admin/", admin.site.urls),

    path('upload/', views.UploadTemplateView.as_view(), name='upload_template'),
    path('format/', views.format_template, name='format_template'),
    path('validate/', views.validate_template, name='validate_template'),
    path('analysis/', views.AnalysisListView.as_view(), name='analysis_list'),
    path('analysis/<int:pk>/', views.AnalysisDetailView.as_view(), name='analysis_detail'),
    path('analysis/<int:pk>/delete/', views.AnalysisDeleteView.as_view(), name='analysis_delete'),
    path("export_analysis/<int:pk>/", export_analysis, name="export_analysis"),

    # Ollama API endpoints
    path('api/ollama/models/', api_views.list_ollama_models, name='list_ollama_models'),
    path('api/ollama/set-model/', api_views.set_ollama_model, name='set_ollama_model'),
    path('api/ollama/security/', api_views.analyze_security_issue, name='analyze_security_issue'),
    path('api/ollama/fixes/', api_views.suggest_template_fixes, name='suggest_template_fixes'),
    path('api/ollama/cost/', api_views.optimize_cost, name='optimize_cost')
]
