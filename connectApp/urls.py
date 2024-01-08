from django.contrib import admin
from django.urls import path, include
from .views import LoginView, LogoutView, SignupAPIView, RedirectShopifyView, AuthorizeShopifyView, AuthorizeGoogleView

app_name = 'connectApp'

urlpatterns = [
    path('', LoginView.as_view(), name='login'),
    path('signup/', SignupAPIView.as_view(), name='sign_up'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('shopify/redirect', RedirectShopifyView.as_view(), name='redirect_shopify'),
    path('shopify/authorize', AuthorizeShopifyView.as_view(), name='authorize_shopify'),
    path('google/authorize', AuthorizeGoogleView.as_view(), name='authorize_google'),
]