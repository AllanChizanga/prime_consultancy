from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from . import views

# Create a router and register our viewsets with it.
router = DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'csr', views.CsrViewSet)
router.register(r'fiscal-days', views.FiscalDayViewSet)
router.register(r'receipts', views.ReceiptViewSet)
router.register(r'buyers', views.BuyerViewSet)
router.register(r'credit-debit-notes', views.CreditDebitNoteViewSet)

# The API URLs are now determined automatically by the router.
urlpatterns = [
    # Authentication URLs
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    
    # Web Template URLs
    path('', views.home, name='home'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('registered-clients/', views.registered_clients, name='registered_clients'),
    path('device-status/<int:user_id>/', views.device_status, name='device_status'),
    path('client-info/<int:user_id>/', views.device_status, name='client_info'),
    path('client-activation/<int:user_id>/', views.client_activation, name='client_activation'),
    path('client-deactivation/<int:user_id>/', views.client_deactivation, name='client_deactivation'),
    path('register-new-device/<int:user_id>/', views.register_new_device, name='register_new_device'),
    path('device-config/<int:user_id>/', views.device_config, name='device_config'),
    path('confirm-device-reg/<int:user_id>/', views.confirm_device_reg, name='confirm_device_reg'),
    path('submit-receipt/', views.submit_receipt_view, name='submit_receipt'),
    path('submit-invoice/', views.submit_invoice_view, name='submit_invoice'),
    path('open-fiscal-day/', views.open_fiscal_day, name='open_fiscal_day'),
    path('close-fiscal-day/', views.close_fiscal_day, name='close_fiscal_day'),
    path('profile/', views.profile, name='profile'),
    path('change-password/', views.change_password_view, name='change_password'),
    path('logout/', views.logout_view, name='logout'),
    
    # API URLs
    path('api/', include(router.urls)),
    path('api-auth/', include('rest_framework.urls')),
    path('start-xero-auth/', views.start_xero_auth_view, name='start-xero-auth'),
    
    # JWT Token URLs
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
]