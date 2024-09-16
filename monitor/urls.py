# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('api/notifications/dao', views.dao_notifications, name='dao_notifications'),
    path('api/notifications/secbox', views.secbox_notifications, name='secbox_notifications'),
]
