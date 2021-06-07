from django.contrib import admin
from .models import Payment, Order, OrderProduct

# Register your models here.


class OrderProductInline(admin.TabularInline):
    model = OrderProduct
    readonly_fields = ('payment', 'user', 'product', 'quantity', 'product_price', 'ordered')
    extra = 0
    
    
class OrderAdmin(admin.ModelAdmin):
    list_display = ['fullname', 'email','phone', 'order_number' , 'city', 'order_total' , 'status' , 'is_ordered']
    list_filter = ['status', 'is_ordered']
    list_search = ['order_number','first_name' , 'last_name' , 'email']
    list_per_page = 20
    inlines = [OrderProductInline]

admin.site.register(Payment)
admin.site.register(Order,OrderAdmin)
admin.site.register(OrderProduct)