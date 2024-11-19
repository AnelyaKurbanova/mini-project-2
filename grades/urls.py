from django.urls import path
from .views import GradeListView, GradeDetailView

urlpatterns = [
    path('', GradeListView.as_view(), name='grade-list'),
    path('<int:pk>/', GradeDetailView.as_view(), name='grade-detail'),
]
