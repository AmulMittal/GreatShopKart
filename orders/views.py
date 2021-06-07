
from django.http.response import JsonResponse
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from store.models import Variation
from orders.forms import OrderForm
from django.shortcuts import render , redirect
from django.http import HttpResponse
from cart.models import CartItem
from store.models import Product

from .models import Order , Payment , OrderProduct
import datetime
import json

# Create your views here.

def payment(request):
    body = json.loads(request.body)
    order = Order.objects.get(user=request.user, is_ordered = False , order_number = body['orderID'])
    
    # store transaction detials inside payment model
    payment = Payment(
        user = request.user,
        payment_id = body['transID'],
        payment_method = body['payment_method'],
        amount_paid = order.order_total,
        status = body['status'],
    )
    
    payment.save()
    order.payment = payment
    order.is_ordered = True
    order.save()
    
    # move the cart items to orderproduct table
    cart_items = CartItem.objects.filter(user=request.user)
    for item in cart_items:
        orderproduct = OrderProduct()
        orderproduct.order_id = order.id
        orderproduct.payment = payment
        orderproduct.user_id = request.user.id
        orderproduct.product_id = item.product_id
        orderproduct.quantity = item.quantity
        orderproduct.product_price = item.product.price
        orderproduct.ordered = True
        orderproduct.save()
        
        cart_item = CartItem.objects.get(id=item.id)
        product_variations = cart_item.variations.all()
        orderproduct.variations.set(product_variations)
        orderproduct.save()
        
        
        
        # reduce the quanity of the sold products
        product = Product.objects.get(id=item.product_id)
        product.stock -= item.quantity
        product.save()
        
        
    # Clear cart
    CartItem.objects.filter(user=request.user).delete()
    
        
    
    # Send order recieved email to customer
    mail_subject = 'Thanks for the shopping from GreatKart'
    message = render_to_string('orders/order_recieved_email.html',{
        'user' : request.user,
        'order' : order,
    })
    to_email = request.user.email
    send_email = EmailMessage(mail_subject , message , to=[to_email])
    send_email.send()
    
    # Send order number and transaction id back to senddata method via JsonResponse
    data = {
        'order_number' : order.order_number,
        'transID' : payment.payment_id,
    }
    
    return JsonResponse(data)

def place_order(request):
    current_user = request.user
    
    cart_items = CartItem.objects.filter(user=current_user)
    count = cart_items.count()
    if count <= 0:
        return redirect('store')
        
    total=0
    # quantity=0
    grand_total = 0
    tax = 0
    
    for cart_item in cart_items:
        total += (cart_item.product.price * cart_item.quantity)
        # quantity += cart_item.quantity
        tax = 0.02 * total
        grand_total = total + tax
    
    

    
    # if user has some cart_items, i.e count > 0
    if request.method == 'POST':
        form = OrderForm(request.POST)
        if form.is_valid():
            # store all the billing details in the store table
            data = Order()
            data.user = current_user
            data.first_name = form.cleaned_data['first_name']
            data.last_name = form.cleaned_data['last_name']
            data.email = form.cleaned_data['email']
            data.phone = form.cleaned_data['phone']
            data.address_line_1 = form.cleaned_data['address_line_1']
            data.address_line_2 = form.cleaned_data['address_line_2']
            data.country = form.cleaned_data['country']
            data.state = form.cleaned_data['state']  
            data.city = form.cleaned_data['city']
            data.order_note = form.cleaned_data['order_note']
            
            data.order_total = grand_total
            data.tax = tax
           
            data.ip = request.META.get('REMOTE_ADDR')
            data.save()
            
            # Generate order number
            
            yr = int(datetime.date.today().strftime('%Y'))
            mt = int(datetime.date.today().strftime('%m'))
            dt = int(datetime.date.today().strftime('%d'))
            
            
            d = datetime.date(yr,mt,dt)
            current_date = d.strftime("%Y%m%d")
            
            order_number = current_date + str(data.id)
            print(order_number , "order_number")
            data.order_number = order_number
            data.save()
            
            order = Order.objects.get(user=current_user, is_ordered = False , order_number = order_number)
            context = {
                'order' : order,
                'cart_items' : cart_items,
                'total' : total,
                'tax' : tax,
                'grand_total' : grand_total
            }
            return render(request, 'orders/payment.html', context)   
        else: 
            print("not valid form")
            print(form.errors)
            return redirect('checkout')   
        
def order_complete(request):
    order_number = request.GET['order_number']
    transID = request.GET['payment_id']
    
    try:
        order = Order.objects.get(order_number = order_number, is_ordered = True)
        order_products = OrderProduct.objects.filter(order=order)
        payment = Payment.objects.get(payment_id = transID)
        
        subtotal = 0
        for item in order_products:
            subtotal += item.product_price * item.quantity
            
        context = {
            'order' : order,
            'order_number' : order_number,
            'ordered_products' : order_products,
            'transID' : transID,
            'payment' : payment,
            'subtotal' : subtotal,
        }
            
        return render(request, 'orders/order_complete.html',context)
    except(Payment.DoesNotExist , Order.DoesNotExist):
        return redirect('home')
        
   
          
             
             
        
    