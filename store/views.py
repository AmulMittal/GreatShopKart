from django.shortcuts import render, get_object_or_404 , redirect
from store.models import Category, Product , ReviewRating
from cart.models import Cart, CartItem 
from cart.views import _cart_id
from django.core.paginator import Paginator , EmptyPage , PageNotAnInteger
from django.db.models import Q
from .forms import ReviewForm
from django.contrib import messages
from orders.models import OrderProduct
# Create your views here.




def store(request , category_slug=None):
    categories = None
    products = None
    
    if category_slug != None:
        categories = get_object_or_404(Category, slug = category_slug)
        products = Product.objects.filter(category = categories , is_available = True)
        paginator = Paginator(products,2)
        page = request.GET.get('page')
        paged_products = paginator.get_page(page)
        products_count = products.count()
    else:
        products = Product.objects.all().filter(is_available=True).order_by('id')
        paginator = Paginator(products,2)
        page = request.GET.get('page')
        paged_products = paginator.get_page(page)
        products_count = products.count()
        
    context = {
        'products':paged_products,
        'products_count':products_count,
    }
    return render(request , 'store/store.html',context)


def product_detail(request, category_slug, product_slug):
    try:
        single_product = Product.objects.get(category__slug = category_slug, slug = product_slug)
        is_addedtocart = CartItem.objects.filter(cart__cart_id = _cart_id(request) , product = single_product).exists()
     
    except Exception as e:
        raise e
    try:
        orderproducts = OrderProduct.objects.filter(user=request.user , product_id = single_product.id).exists()
    except OrderProduct.DoesNotExist:
        orderproducts = None
        
    
    context = {
        'single_product':single_product,
        'is_addedtocart':is_addedtocart,
        'orderproducts':orderproducts,
    }
    return render(request, 'store/product_detail.html', context)


def search(request):
    if 'keyword' in request.GET:
        keyword = request.GET['keyword']
        if keyword:
            products = Product.objects.filter( Q(description__icontains=keyword) | Q(product_name__icontains=keyword) )
            products_count = products.count()
    context = {
        'products': products,
        'products_count':products_count,
    }
    return render(request, 'store/store.html', context)

def submit_review(request, product_id):
    url = request.META.get('HTTP_REFERER')  # gets the url you are coming from . i.e just previous url , after completing this function
    try:
        # updating reviews if exists
        reviews = ReviewRating.objects.get(user__id = request.user.id , product__id = product_id)
        form = ReviewForm(request.POST , instance = reviews)
        form.save()
        messages.success(request, 'Thank you! Your review has been updated.')
        return redirect(url)
    except ReviewRating.DoesNotExist:
        form = ReviewForm(request.POST)
        if form.is_valid():
            data = ReviewRating()
            data.subject = form.cleaned_data['subject']
            data.rating = form.cleaned_data['rating']
            data.review = form.cleaned_data['review'] 
            data.ip = request.META.get('REMOTE_ADDR')
            data.product_id = product_id
            data.user_id = request.user.id
            data.save()
            messages.success(request, 'Thank you! Your review has been submitted.')
            return redirect(url)
            
        


    





