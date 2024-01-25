from django.views import View
from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from .seriallizers import UserSerializer
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.utils.decorators import method_decorator
import requests, json
from .models import UserConnections, ShopifyData
from django.contrib import messages
from google_auth_oauthlib.flow import InstalledAppFlow
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from datetime import datetime, timedelta, timezone

SCOPES_GOOGLE = ['https://www.googleapis.com/auth/spreadsheets']
REDIRECT_URL_GOOGLE = "http://localhost:9000/api/callback_google"

def create_spread_sheet(user_id, sheet_name):
    try:
        user = UserConnections.objects.get(user_id=user_id, platform='google')
        data = {}
        values =  [ {
                        "userEnteredValue": {
                            "stringValue": "title"
                        }
                        },
                        {
                        "userEnteredValue": {
                            "stringValue": "product_id"
                        }
                        },
                        {
                        "userEnteredValue": {
                            "stringValue": "product_type"
                        }
                        },
                        {
                        "userEnteredValue": {
                            "stringValue": "price"
                        }
                        },
                        {
                        "userEnteredValue": {
                            "stringValue": "vendor"
                        }
                        },
                        {
                        "userEnteredValue": {
                            "stringValue": "created_at"
                        }
                        },
                        {
                        "userEnteredValue": {
                            "stringValue": "updated_at"
                        }
                        }]

        url = "https://sheets.googleapis.com/v4/spreadsheets"

        payload = json.dumps({
        "properties": {
            "title": sheet_name
        },
        "sheets": [
            {
            "data": [
                {
                "rowData": [
                    {
                    "values": values
                    }
                ]
                }
            ],
            "properties": {
                "title": "Sheet1"
            }
            }
        ]
        })
        headers = {
        'Authorization': f'Bearer {user.access_token}',
        'Content-Type': 'application/json'
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        if response.status_code==200:
            response=response.json()
            google_user, created = UserConnections.objects.update_or_create(
            user_id=user_id,
            platform='google',
            defaults={'spreadsheet_id': response['spreadsheetId']}
        )
            return True
        return False
    except Exception as e:
        return False

def get_flow(client_id, client_secret, project_id):
    flow = InstalledAppFlow.from_client_config(
    {
        "installed": {
            "client_id": client_id,
            "client_secret": client_secret,
            "project_id": project_id,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://accounts.google.com/o/oauth2/token",
        }
    },
    scopes=SCOPES_GOOGLE,
    redirect_uri=REDIRECT_URL_GOOGLE,
    )
    return flow

def sync_check(user_id):
    try:
        user_data = UserConnections.objects.filter(user_id=user_id).all()
        sync_response={'google_synced': False, 'is_spreadsheet': False, 'shopify_synced': False}

        data_dict = {
            'google_access_token': None,
            'shopify_access_token': None,
            'shop': None,
            'spreadsheet_id': None
        }

        for connection in user_data:
            platform = connection.platform
            data_dict[f'{platform}_access_token'] = connection.access_token
            if platform == 'shopify':
                data_dict['shop'] = connection.shop
            else:
                data_dict['spreadsheet_id'] = connection.spreadsheet_id

        if data_dict['spreadsheet_id']:
            sync_response['is_spreadsheet']=True

        if any(value is None for value in data_dict.values()):
            return sync_response

        shopify_url = f"https://{data_dict['shop']}.myshopify.com/admin/api/2024-01/products.json"
        shopify_header = {
            'Content-Type': 'application/json',
            'X-Shopify-Access-Token': data_dict['shopify_access_token']
            }
        shopify_response = requests.get(shopify_url, headers=shopify_header)
        if shopify_response.status_code == 200:
            sync_response['shopify_synced']=True
        google_url = f"https://sheets.googleapis.com/v4/spreadsheets/{data_dict['spreadsheet_id']}/values/Sheet1!A1:Z1"
        google_response = requests.get(google_url, headers={'Authorization': f'Bearer {data_dict["google_access_token"]}'})
        if google_response.status_code == 200:
            sync_response['google_synced']=True
        return sync_response
    except Exception:
        return {'google_synced': False, 'is_spreadsheet': False, 'shopify_synced': False}

class SignupAPIView(View):
    def post(self, request): 
        serializer = UserSerializer(data=request.POST)
        if serializer.is_valid():
            serializer.save()
            return redirect('connectApp:login')
        return HttpResponse(serializer.errors, status=400)

    def get(self, request):
        return render(request, 'signup.html')


@method_decorator(login_required, name='dispatch')
class SidebarView(View):
    def get(self, request):
        user_id = request.session['user_id']
        is_synced = sync_check(user_id)
        return render(request, 'sidebar.html', is_synced)


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
            is_synced = sync_check(user.id)
            print('synceddddddddddddddddddddd', is_synced)
            return render(request, 'sidebar.html', is_synced)
        else:
            return render(request, 'login.html', {'error': 'Invalid login credentials'})


@method_decorator(login_required, name='dispatch')
class LogoutView(View):
    def get(self, request):
        logout(request)
        return redirect('connectApp:login')


class RedirectShopifyView(View):
    def get(self, request):
        return render(request, 'success_shopify.html')


@method_decorator(login_required, name='dispatch')
class AuthorizeShopifyView(View):
    def get(self, request):
        shop = request.GET.get('shop')
        access_token = request.GET.get('access_token')
        user_id = request.session.get('user_id', '')
        url = f"https://{shop}.myshopify.com/admin/api/2024-01/products.json"
        payload = {}
        headers = {
            'Content-Type': 'application/json',
            'X-Shopify-Access-Token': access_token
        }
        response = requests.get(url, headers=headers, data=payload)

        if response.status_code == 200:
            google_user, created = UserConnections.objects.update_or_create(
                user_id=user_id,
                platform='shopify',
                defaults={
                    'access_token': access_token,
                    'shop': shop
                }
            )
            return render(request, 'success_shopify.html')
        else:
            messages.error(request, 'Failed to fetch data from Shopify API. Invalid credentials.')
            return render(request, 'error_shopify.html')


@method_decorator(login_required, name='dispatch')
class AuthorizeGoogleViewV2(View):
    def get(self, request):
        client_id = request.GET.get('client_id')
        client_secret = request.GET.get('client_secret')
        project_id = request.GET.get('project_id')
        spread_sheet_name = request.GET.get('spreadsheet_name')
        request.session['client_id'] = client_id
        request.session['client_secret'] = client_secret
        request.session['project_id'] = project_id
        request.session['spreadsheet_name'] = spread_sheet_name
        flow = get_flow(client_id, client_secret, project_id)
        authorization_url, _ = flow.authorization_url(prompt='consent')
        return redirect(authorization_url)


@method_decorator(login_required, name='dispatch')
class CallBackGoogle(View):
    def get(self, request):
        authorization_code = request.GET.get("code")
        client_id=request.session['client_id']
        client_secret=request.session['client_secret']
        project_id=request.session['project_id']
        user_id=request.session['user_id']
        flow = get_flow(client_id, client_secret, project_id)
        credentials = flow.fetch_token(
            authorization_response=f"{REDIRECT_URL_GOOGLE}?code={authorization_code}",
            **{"insecure_transport": True}
        )

        google_user, created = UserConnections.objects.update_or_create(
            user_id=user_id,
            platform='google',
            defaults={
                'access_token': credentials["access_token"],
                'refresh_token': credentials["refresh_token"]
            }
        )
        if not google_user.spreadsheet_id:
            spreadsheet_name = request.session['spreadsheet_name']
            create_sheet = create_spread_sheet(user_id, spreadsheet_name)
        return redirect('connectApp:redirect_shopify')


@method_decorator(login_required, name='dispatch')
class SyncShopifydata(View):    
    def get(self,request):
        try:
            user_id = request.session['user_id']
            user_data = UserConnections.objects.filter(user_id=user_id).all()
            all_data = ShopifyData.objects.filter(user_id=user_id, is_deleted=False, sync_flag='pending').order_by('-updated_at')[:100]
            print(all_data)
            if all_data:
                data_dict = {
                    'google_access_token': None,
                    'spreadsheet_id': None
                }
                for connection in user_data:
                    platform = connection.platform
                    if platform == 'google':
                        data_dict['google_access_token'] = connection.access_token
                        data_dict['spreadsheet_id'] = connection.spreadsheet_id

                if any(value is None for value in data_dict.values()):
                    raise ValueError("Error: Missing required connection information.")

                google_header = {'Authorization': f'Bearer {data_dict["google_access_token"]}'}

                for data in all_data:
                    google_sheet_payload = [data.title, data.product_id, data.product_type, data.price, data.vendor, str(data.created_at), str(data.updated_at)]
                    print(google_sheet_payload)
                    if not data.row_range:
                        url = f"https://sheets.googleapis.com/v4/spreadsheets/{data_dict['spreadsheet_id']}/values/Sheet1!A:Z:append?valueInputOption=USER_ENTERED"
                        payload = json.dumps({"values": [google_sheet_payload]})
                        response = requests.post(url, headers=google_header, data=payload)
                        print(response.status_code)
                        if response.status_code==200:
                            response = response.json()
                            shopify_data, created = ShopifyData.objects.update_or_create(
                                user_id=user_id,
                                product_id=data.product_id,
                                defaults={
                                'row_range': response["updates"]["updatedRange"],
                                'sync_flag': 'synced'
                                }
                            )
                    else:
                        google_url = f"https://sheets.googleapis.com/v4/spreadsheets/{data_dict['spreadsheet_id']}/values/{data.row_range}"
                        payload = {
                            'values': [google_sheet_payload]
                        }
                        params = {
                            'valueInputOption': 'USER_ENTERED',
                        }
                        response = requests.put(google_url, headers=google_header, params=params, json=payload)
                        if response.status_code==200:
                            shopify_data, created = ShopifyData.objects.update_or_create(
                                user_id=user_id,
                                product_id=data.product_id,
                                defaults={
                                'sync_flag': 'synced'
                                }
                            )
                return render(request, 'syncdata.html', {'message': 'Data Synced successfully'})
            return render(request, 'syncdata.html', {'message': 'No data to sync'})

        except Exception as e:
            return render(request, 'syncdata.html', {'message': str(e)})
class PullShopifydata(View):
    def get(self, request):
        user_id = request.session.get('user_id')
        user_data = UserConnections.objects.filter(user_id=user_id).all()
        last_shopify_data = ShopifyData.objects.filter(user_id=user_id).order_by('-updated_at').first()
        data_dict = {
            'shopify_access_token': None,
            'shop': None,
        }
        for connection in user_data:
            platform = connection.platform
            if platform == 'shopify':
                data_dict['shopify_access_token'] = connection.access_token
                data_dict['shop'] = connection.shop

        if any(value is None for value in data_dict.values()):
            raise ValueError("Error: Missing required connection information.")
        products_list = []
        shopify_url = f"https://{data_dict['shop']}.myshopify.com/admin/api/2024-01/products.json"
        if last_shopify_data:
            original_datetime = datetime.strptime(str(last_shopify_data.updated_at), "%Y-%m-%d %H:%M:%S%z")
            new_datetime = original_datetime + timedelta(seconds=1)
            shopify_url = f"https://{data_dict['shop']}.myshopify.com/admin/api/2024-01/products.json?updated_at_min={new_datetime}"

        shopify_header = {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': data_dict['shopify_access_token']
        }
        response = requests.request("GET", shopify_url, headers=shopify_header)
        if response.status_code==200:
            response=response.json()
            if response["products"]:
                for i in response["products"]:
                    shopify_data, created = ShopifyData.objects.update_or_create(
                        user_id=user_id,
                        product_id=i["id"],
                        defaults={
                        'title': i["title"],
                        'product_type': i["product_type"],
                        'price': i["variants"][0]["price"],
                        'vendor': i["vendor"],
                        'created_at': i["created_at"],
                        'updated_at': i["updated_at"],
                        'sync_flag': 'pending'
                        }
                    )
        all_data = ShopifyData.objects.filter(user_id=user_id, is_deleted=False, sync_flag='pending').order_by('-updated_at')
        paginator = Paginator(all_data, 10)
        page = request.GET.get('page')

        try:
            data = paginator.page(page)
        except PageNotAnInteger:
            data = paginator.page(1)
        except EmptyPage:
            data = paginator.page(paginator.num_pages)

        return render(request, 'shopify_data.html', {'data': data})