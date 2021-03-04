from django.conf.urls import url
from rest_framework.authtoken.views import obtain_auth_token
from .views import CreateUserAPIView, LogoutUserAPIView, ObtainAuthToken


urlpatterns = [
    url(r'^auth/login/$',
        ObtainAuthToken.as_view(),
        name='auth_user_login'),
    url(r'^auth/register/$',
        CreateUserAPIView.as_view(),
        name='auth_user_create'),
    url(r'^auth/logout/$',
        LogoutUserAPIView.as_view(),
        name='auth_user_logout')
]
