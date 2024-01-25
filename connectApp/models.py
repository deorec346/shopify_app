from django.db import models

class UserConnections(models.Model):
    class Platform(models.TextChoices):
        SHOPIFY = 'shopify'
        GOOGLE = 'google'
    user_id = models.CharField(max_length=100)
    access_token =  models.CharField(max_length=250, default='')
    platform = models.CharField(max_length=100, choices=Platform.choices)
    shop = models.CharField(max_length=100, default='')
    refresh_token = models.CharField(max_length=250, default='')
    spreadsheet_id = models.CharField(max_length=250, default='')
    
    
class ShopifyData(models.Model):
    user_id = models.CharField(max_length=100)
    title = models.CharField(max_length=100)
    product_id = models.CharField(max_length=100)
    product_type = models.CharField(max_length=100)
    price = models.CharField(max_length=100)
    vendor = models.CharField(max_length=100)
    created_at = models.DateTimeField()  
    updated_at = models.DateTimeField()
    is_deleted = models.BooleanField(default=False)
    row_range = models.CharField(max_length=100, default='')
    sync_flag = models.CharField(max_length=10, default='pending')

    def __str__(self):
        return f"{self.title} - {self.product_id}"