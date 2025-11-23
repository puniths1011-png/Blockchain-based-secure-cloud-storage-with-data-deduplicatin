"""Blockchain_Based_Decentralized_Cloud_Storage URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
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
from django.urls import path
from MainApp import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index),
    path('owner', views.owner),
    path('owner_register', views.owner_register),
    path('OregAction', views.OregAction),
    path('Owner_login', views.Owner_login),
    path('owner_home', views.owner_home),
    path('upload_file', views.upload_file),
    path('upload_file_Action', views.upload_file_Action),
    path('view_files', views.view_files),
    path('blockchain', views.blockchain),
    path('Blockchain_login', views.Blockchain_login),
    path('blockchain_home', views.blockchain_home),
    path('view_fileDetails', views.view_fileDetails),
    path('ipfs', views.ipfs),
    path('ipfs_logAction', views.ipfs_logAction),
    path('ipfs_home', views.ipfs_home),
    path('view_IPFSfileDetails', views.view_IPFSfileDetails),
]
