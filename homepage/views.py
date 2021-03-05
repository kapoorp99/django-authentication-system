from django.http import JsonResponse


# Create your views here.
def homepage(request):
    message = {
        "status": "200",
        "message": "API application is up and running good."
    }
    return JsonResponse(data=message)
