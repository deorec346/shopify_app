from django.db import models

class ShopifyUser(models.Model):
    user_id = models.CharField(max_length=100)
    access_token = models.CharField(max_length=100)
    shop = models.CharField(max_length=100)


class GoogleUser(models.Model):
    user_id = models.CharField(max_length=100)
    client_id = models.CharField(max_length=100)
    client_secret = models.CharField(max_length=100)
    project_id = models.CharField(max_length=100)