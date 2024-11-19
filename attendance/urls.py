from django.urls import path
from .views import AttendanceListView, BulkAttendanceView, AttendanceDetailView, BulkUpdateAttendanceView

urlpatterns = [
    path('', AttendanceListView.as_view(), name='attendance-list'),
    path('<int:pk>/', AttendanceDetailView.as_view(), name='attendance-detail'),
    path('bulk/', BulkAttendanceView.as_view(), name='attendance-bulk'),
    path('bulk-update/', BulkUpdateAttendanceView.as_view(), name='attendance-bulk-update'),
]
