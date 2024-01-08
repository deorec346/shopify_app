from django.views import View
from django.shortcuts import render, redirect
from django.http import HttpResponse
from .seriallizers import UserSerializer
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.utils.decorators import method_decorator
import requests, yaml, json
from .models import ShopifyUser, GoogleUser
from django.contrib import messages
from pydrive.auth import GoogleAuth

class SignupAPIView(View):
    def post(self, request): 
        serializer = UserSerializer(data=request.POST)
        if serializer.is_valid():
            serializer.save()
            return redirect('connectApp:login')
        return HttpResponse(serializer.errors, status=400)

    def get(self, request):
        return render(request, 'signup.html')

class LoginView(View):
    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            request.session['user_id'] = user.id

            return render(request, 'sidebar.html')
        else:
            # Handle invalid login
            return render(request, 'login.html', {'error': 'Invalid login credentials'})


@method_decorator(login_required, name='dispatch')
class LogoutView(View):
    def get(self, request):
        logout(request)
        return redirect('connectApp:login')

@method_decorator(login_required, name='dispatch')
class RedirectShopifyView(View):
    def get(self, request):
        return render(request, 'success_shopify.html')

@method_decorator(login_required, name='dispatch')
class AuthorizeShopifyView(View):
    def get(self, request):
        shop = request.GET.get('shop')
        access_token = request.GET.get('access_token')
        user_id = request.session.get('user_id', '')
        # print("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS", shop, access_token, user_id)
        url = f"https://{shop}.myshopify.com/admin/api/2024-01/products.json"
        # print("URLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL", url)
        payload = {}
        headers = {
            'Content-Type': 'application/json',
            'X-Shopify-Access-Token': access_token
        }

        response = requests.get(url, headers=headers, data=payload)
        # print("ddddddddddddddddddddddddddddd", url, payload)

        if response.status_code == 200:

            shopify_user, created = ShopifyUser.objects.update_or_create(
                user_id=user_id,
                defaults={'access_token': access_token, 'shop': shop}
            )
            return render(request, 'success_shopify.html')
        else:
            messages.error(request, 'Failed to fetch data from Shopify API. Invalid credentials.')
            return render(request, 'error_shopify.html')


@method_decorator(login_required, name='dispatch')
class AuthorizeGoogleView(View):
    def get(self, request):
        client_id = request.GET.get('client_id')
        client_secret = request.GET.get('client_secret')
        project_id = request.GET.get('project_id')
        user_id = request.session.get('user_id', '')
        client_secrets_path = '/client_secrets.json'
        file_path = 'D:\ConstaCloud\shopify_app\client_secrets.json'
        data = {"installed":{"client_id": client_id,
                             "project_id":project_id,
                             "auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs",
                             "client_secret":client_secret,
                             "redirect_uris":["http://localhost"]}}

        update_dict = {
            'client_config_backend': 'file',
            'client_config':{'client_id': client_id,
            'client_secret': client_secret},
            'oauth_scope': ['https://www.googleapis.com/auth/drive'],
            'get_refresh_token': True,
            'save_credentials': True,
            'save_credentials_backend': 'file',
            'save_credentials_file': 'credentials.json',
        }
        with open(file_path, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        yaml_path = 'D:\ConstaCloud\shopify_app\settings.yaml'
        with open(yaml_path, 'r') as yaml_file:
            data = yaml.safe_load(yaml_file)

        for key, value in update_dict.items():
            data[key] = value

        with open(yaml_path, 'w') as yaml_file:
            yaml.dump(data, yaml_file, default_flow_style=False)

        gauth = GoogleAuth(settings_file=client_secrets_path)
        gauth.LocalWebserverAuth()
        
        if gauth.credentials:
            shopify_user, created = GoogleUser.objects.update_or_create(
                user_id=user_id,
                defaults={'client_id': client_id, 'client_secret': client_secret, 'project_id': project_id, 'user_id': user_id}
            )
            return redirect('connectApp:sidebar')  # Use your actual URL name for the sidebar view
        else:
            messages.error(request, 'Failed to fetch data from Google API.')
            return render(request, 'sidebar.html')