from django.contrib import admin
from django.urls import path
from .views import LoginView, LogoutView, SignupAPIView,SidebarView, RedirectShopifyView, AuthorizeShopifyView, AuthorizeGoogleViewV2, CallBackGoogle,PullShopifydata,SyncShopifydata
app_name = 'connectApp'

urlpatterns = [
    path('', LoginView.as_view(), name='login'),
    path('signup/', SignupAPIView.as_view(), name='sign_up'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('redirect/sidebar', SidebarView.as_view(), name='sidebar'),
    path('shopify/redirect', RedirectShopifyView.as_view(), name='redirect_shopify'),
    path('shopify/authorize', AuthorizeShopifyView.as_view(), name='authorize_shopify'),
    path('google/authorize', AuthorizeGoogleViewV2.as_view(), name='authorize_google'),
    path('callback_google', CallBackGoogle.as_view(), name='callbackGoogle'),
    path('sync_data', SyncShopifydata.as_view(), name='sync_data'),
    path('get_data', PullShopifydata.as_view(), name='get_data'),
]