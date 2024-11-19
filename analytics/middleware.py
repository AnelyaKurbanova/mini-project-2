from analytics.models import APIRequestLog
from django.utils.timezone import now


class APILogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.user.is_authenticated:
            APIRequestLog.objects.create(
                user=request.user,
                endpoint=request.path,
                method=request.method,
                timestamp=now(),
            )
        return response
