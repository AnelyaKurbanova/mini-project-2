from django.urls import path
from .views import AnalyticsDashboard

urlpatterns = [
    path('dashboard/', AnalyticsDashboard.as_view(), name='analytics-dashboard'),
]
