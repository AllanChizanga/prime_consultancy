from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages
from django.conf import settings
from django.db.models import Count, Q
import os
import json
import requests
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken
import urllib3
from .models import User, FiscalDay, Receipt, ReceiptLine, ReceiptTax, Buyer, CreditDebitNote, Csr, ReceiptSubmissionLog
from .serializers import (
    UserSerializer, FiscalDaySerializer, ReceiptSerializer, 
    ReceiptLineSerializer, ReceiptTaxSerializer, BuyerSerializer,
    CreditDebitNoteSerializer, CsrSerializer, ReceiptSubmissionLogSerializer
)

# Disable SSL warnings for test environment
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import re
import textwrap
from oauth2client.client import OAuth2Credentials

class IsAdminOrSelf(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return request.user.is_staff or request.user.is_superuser or obj == request.user

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrSelf]

    def get_permissions(self):
        if self.action == 'create':
            return []
        return super().get_permissions()

    def get_queryset(self):
        if self.request.user.is_staff or self.request.user.is_superuser:
            return User.objects.all()
        return User.objects.filter(id=self.request.user.id)

    @action(detail=False, methods=['post'], permission_classes=[])
    def login(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(request, email=email, password=password)
        
        if user:
            login(request, user)
            refresh = RefreshToken.for_user(user)
            serializer = self.get_serializer(user)
            return Response({
                'user': serializer.data,
                'tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }
            })
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def refresh_token(self, request):
        refresh_token = request.data.get('refresh')
        try:
            refresh = RefreshToken(refresh_token)
            return Response({
                'access': str(refresh.access_token)
            })
        except Exception as e:
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def logout(self, request):
        try:
            refresh_token = request.data.get('refresh')
            token = RefreshToken(refresh_token)
            token.blacklist()
            logout(request)
            return Response({'message': 'Successfully logged out'})
        except Exception:
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        if not request.user.is_staff and not request.user.is_superuser:
            return Response({'error': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)
        user = self.get_object()
        user.is_active = True
        user.save()
        return Response({'message': 'User activated successfully'})

    @action(detail=True, methods=['post'])
    def deactivate(self, request, pk=None):
        if not request.user.is_staff and not request.user.is_superuser:
            return Response({'error': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)
        user = self.get_object()
        user.is_active = False
        user.save()
        return Response({'message': 'User deactivated successfully'})

    @action(detail=False, methods=['post'])
    def register(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.set_password(request.data.get('password'))
            user.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def change_password(self, request, pk=None):
        user = self.get_object()
        form = PasswordChangeForm(user, request.data)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            return Response({"detail": "Password successfully changed"})
        return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

class FiscalDayViewSet(viewsets.ModelViewSet):
    queryset = FiscalDay.objects.all()
    serializer_class = FiscalDaySerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=['post'])
    def open_fiscal_day(self, request):
        user = request.user
        current_datetime = timezone.now()
        
        # Check if fiscal day is already open
        open_fiscal_day = FiscalDay.objects.filter(
            user=user,
            day_closed__isnull=True
        ).first()

        if open_fiscal_day:
            return Response(
                {'error': 'A fiscal day is already open'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create new fiscal day
        fiscal_day = FiscalDay.objects.create(
            user=user,
            day_opened=current_datetime
        )
        
        serializer = self.get_serializer(fiscal_day)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def close_fiscal_day(self, request):
        user = request.user
        current_datetime = timezone.now()
        
        # Get open fiscal day
        fiscal_day = FiscalDay.objects.filter(
            user=user,
            day_closed__isnull=True
        ).first()

        if not fiscal_day:
            return Response(
                {'error': 'No open fiscal day found'},
                status=status.HTTP_400_BAD_REQUEST
            )

        fiscal_day.day_closed = current_datetime
        fiscal_day.save()
        
        serializer = self.get_serializer(fiscal_day)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def submit_receipt(self, request):
        user = request.user
        receipt_data = request.data.get('receipt')
        
        if not receipt_data:
            return Response(
                {'error': 'Receipt data is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get open fiscal day
        fiscal_day = FiscalDay.objects.filter(
            user=user,
            day_closed__isnull=True
        ).first()

        if not fiscal_day:
            return Response(
                {'error': 'No open fiscal day found'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Process receipt data here...
        # Add your receipt processing logic

        return Response({'message': 'Receipt submitted successfully'})

class ReceiptViewSet(viewsets.ModelViewSet):
    queryset = Receipt.objects.all()
    serializer_class = ReceiptSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        receipt = serializer.save()
        
        # Handle receipt lines
        receipt_lines_data = self.request.data.get('receipt_lines', [])
        for line_data in receipt_lines_data:
            ReceiptLine.objects.create(receipt=receipt, **line_data)
        
        # Handle receipt taxes
        receipt_taxes_data = self.request.data.get('receipt_taxes', [])
        for tax_data in receipt_taxes_data:
            ReceiptTax.objects.create(receipt=receipt, **tax_data)

    @action(detail=False, methods=['post'])
    def submit_receipt(self, request):
        """Enhanced ZIMRA receipt submission with error handling"""
        user = request.user
        
        # Check if user has valid certificate
        cert_path = os.path.join(settings.BASE_DIR, 'certificates', f'device_cert_{user.id}.pem')
        key_path = os.path.join(settings.BASE_DIR, 'certificates', 'private.key')

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            return Response({
                "detail": "Certificate or key not found. Please ensure device is properly registered.",
                "error_code": "CERT_NOT_FOUND"
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate device configuration
        if not user.device_id or not user.model_name:
            return Response({
                "detail": "Device not properly configured. Please complete device registration.",
                "error_code": "DEVICE_NOT_CONFIGURED"
            }, status=status.HTTP_400_BAD_REQUEST)

        url = f'https://fdmsapitest.zimra.co.zw/Device/v1/{user.device_id}/SubmitReceipt'
        headers = {
            'Content-Type': 'application/json',
            "DeviceModelName": user.model_name,
            "DeviceModelVersion": user.model_version,
        }

        # Create submission log
        receipt_data = request.data.get('receipt')
        if receipt_data:
            try:
                receipt = Receipt.objects.get(id=receipt_data.get('id'))
                submission_log = ReceiptSubmissionLog.objects.create(
                    receipt=receipt,
                    submission_status='PENDING'
                )
            except Receipt.DoesNotExist:
                return Response({
                    "detail": "Receipt not found",
                    "error_code": "RECEIPT_NOT_FOUND"
                }, status=status.HTTP_404_NOT_FOUND)

        try:
            response = requests.post(url, json=request.data, cert=(cert_path, key_path), headers=headers, verify=True, timeout=30)
            response.raise_for_status()
            
            # Update submission log on success
            if receipt_data:
                submission_log.submission_status = 'SUBMITTED'
                submission_log.zimra_response = response.text
                submission_log.zimra_receipt_number = response.json().get('receiptNumber', '')
                submission_log.save()
            
            return Response({
                "success": True,
                "zimra_response": response.json(),
                "submission_id": submission_log.id if receipt_data else None
            })
            
        except requests.exceptions.Timeout:
            if receipt_data:
                submission_log.submission_status = 'FAILED'
                submission_log.error_message = 'Request timeout - ZIMRA server did not respond'
                submission_log.save()
            return Response({
                "detail": "Request timeout. ZIMRA server is not responding. Please try again later.",
                "error_code": "TIMEOUT"
            }, status=status.HTTP_504_GATEWAY_TIMEOUT)
            
        except requests.exceptions.ConnectionError:
            if receipt_data:
                submission_log.submission_status = 'RETRY'
                submission_log.error_message = 'Connection error - network issues'
                submission_log.save()
            return Response({
                "detail": "Network connection error. Please check your internet connection and try again.",
                "error_code": "CONNECTION_ERROR"
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"ZIMRA server error: {e.response.status_code}"
            if receipt_data:
                submission_log.submission_status = 'FAILED'
                submission_log.error_message = error_msg
                submission_log.zimra_response = e.response.text if hasattr(e.response, 'text') else ''
                submission_log.save()
            return Response({
                "detail": error_msg,
                "zimra_response": e.response.text if hasattr(e.response, 'text') else '',
                "error_code": "ZIMRA_SERVER_ERROR"
            }, status=status.HTTP_502_BAD_GATEWAY)
            
        except requests.exceptions.RequestException as e:
            if receipt_data:
                submission_log.submission_status = 'FAILED'
                submission_log.error_message = str(e)
                submission_log.save()
            return Response({
                "detail": f"Request failed: {str(e)}",
                "error_code": "REQUEST_FAILED"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class BuyerViewSet(viewsets.ModelViewSet):
    queryset = Buyer.objects.all()
    serializer_class = BuyerSerializer
    permission_classes = [permissions.IsAuthenticated]

class CreditDebitNoteViewSet(viewsets.ModelViewSet):
    queryset = CreditDebitNote.objects.all()
    serializer_class = CreditDebitNoteSerializer
    permission_classes = [permissions.IsAuthenticated]

class CsrViewSet(viewsets.ModelViewSet):
    queryset = Csr.objects.all()
    serializer_class = CsrSerializer
    permission_classes = [permissions.IsAuthenticated]

    def format_csr_pem(self, csr_string):
        # Remove existing headers, footers, and whitespace
        csr_clean = re.sub(r'-+BEGIN CERTIFICATE REQUEST-+|-+END CERTIFICATE REQUEST-+|\s+', '', csr_string)
        
        # Add proper line breaks every 64 characters
        csr_formatted = '\n'.join(textwrap.wrap(csr_clean, 64))
        
        # Add PEM headers and footers
        return f"-----BEGIN CERTIFICATE REQUEST-----\n{csr_formatted}\n-----END CERTIFICATE REQUEST-----"

    def save_certificate(self, certificate_content, client_id):
        cert_dir = os.path.join(settings.BASE_DIR, 'certificates')
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)
        
        cert_path = os.path.join(cert_dir, f'device_cert_{client_id}.pem')
        with open(cert_path, 'w') as f:
            f.write(certificate_content)
        return cert_path

    @action(detail=True, methods=['post'])
    def register_device(self, request, pk=None):
        user = get_object_or_404(User, pk=pk)
        csr = self.get_object()

        url = "https://fdmsapitest.zimra.co.zw/Device/v1/RegisterDevice"
        headers = {
            "Content-Type": "application/json",
            "DeviceModelName": user.model_name,
            "DeviceModelVersion": user.model_version
        }

        formatted_csr = self.format_csr_pem(csr.mycsr)
        data = {"csr": formatted_csr}

        try:
            response = requests.post(url, json=data, headers=headers, verify=True)
            response.raise_for_status()
            
            certificate = response.json().get('certificate')
            if certificate:
                cert_path = self.save_certificate(certificate, user.id)
                return Response({"detail": "Device registered successfully", "certificate_path": cert_path})
            return Response({"detail": "No certificate in response"}, status=status.HTTP_400_BAD_REQUEST)
        except requests.exceptions.RequestException as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['get'])
    def get_configuration(self, request, pk=None):
        user = get_object_or_404(User, pk=pk)
        url = f"https://fdmsapitest.zimra.co.zw/Device/v1/{user.device_id}/GetConfiguration"
        
        cert_path = os.path.join(settings.BASE_DIR, 'certificates', f'device_cert_{user.id}.pem')
        key_path = os.path.join(settings.BASE_DIR, 'certificates', 'private.key')

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            return Response({"detail": "Certificate or key not found"}, status=status.HTTP_400_BAD_REQUEST)

        headers = {
            "Content-Type": "application/json",
            "DeviceModelName": user.model_name,
            "DeviceModelVersion": user.model_version
        }

        try:
            response = requests.get(url, cert=(cert_path, key_path), headers=headers, verify=False)
            response.raise_for_status()
            return Response(response.json())
        except requests.exceptions.RequestException as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['get'])
    def get_status(self, request, pk=None):
        user = get_object_or_404(User, pk=pk)
        url = f"https://fdmsapitest.zimra.co.zw/Device/v1/{user.device_id}/GetStatus"
        
        cert_path = os.path.join(settings.BASE_DIR, 'certificates', f'device_cert_{user.id}.pem')
        key_path = os.path.join(settings.BASE_DIR, 'certificates', 'private.key')

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            return Response({"detail": "Certificate or key not found"}, status=status.HTTP_400_BAD_REQUEST)

        headers = {
            "Content-Type": "application/json",
            "DeviceModelName": user.model_name,
            "DeviceModelVersion": user.model_version
        }

        try:
            response = requests.get(url, cert=(cert_path, key_path), headers=headers, verify=False)
            response.raise_for_status()
            return Response(response.json())
        except requests.exceptions.RequestException as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def start_xero_auth_view(request):
    credentials = OAuth2Credentials(
        client_id, client_secret, callback_uri=callback_uri,
        scope=[XeroScopes.OFFLINE_ACCESS, XeroScopes.ACCOUNTING_CONTACTS,
               XeroScopes.ACCOUNTING_TRANSACTIONS]
    )
    authorization_url = credentials.generate_url()
    return Response({"authorization_url": authorization_url})

@api_view(['GET'])
def get_routes(request):
    routes = [
        {'name': 'login', 'url': '/api/login/'},
        {'name': 'logout', 'url': '/api/logout/'},
        {'name': 'register', 'url': '/api/register/'},
        {'name': 'get_routes', 'url': '/api/get-routes/'},
        {'name': 'start-xero-auth', 'url': '/api/start-xero-auth/'},
        {'name': 'token_obtain_pair', 'url': '/api/token/'},
        {'name': 'token_refresh', 'url': '/api/token/refresh/'},
        {'name': 'token_verify', 'url': '/api/token/verify/'},
    ]
    return Response({"routes": routes})

# Template-based views
def login_view(request):
    """Login view"""
    if request.user.is_authenticated:
        return redirect('home')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        # Validate input
        if not email or not password:
            return render(request, 'main/login.html', {
                'error': 'Please enter both email and password.'
            })
        
        # Check if user exists first
        try:
            user_check = User.objects.get(email=email)
            
            # Check if user is active
            if not user_check.is_active:
                return render(request, 'main/login.html', {
                    'error': 'Your account has not been activated yet. Please contact the administrator for account activation.'
                })
            
        except User.DoesNotExist:
            return render(request, 'main/login.html', {
                'error': 'No account found with this email address. Please check your email or contact support.'
            })
        
        # Attempt authentication
        user = authenticate(request, email=email, password=password)
        
        if user:
            login(request, user)
            next_url = request.GET.get('next', 'home')
            return redirect(next_url)
        else:
            # User exists and is active but password is wrong
            return render(request, 'main/login.html', {
                'error': 'Invalid password. Please check your password and try again.'
            })
    
    return render(request, 'main/login.html')

def register_view(request):
    """Registration view"""
    if request.user.is_authenticated:
        return redirect('home')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        first_name = request.POST.get('first_name', '')
        last_name = request.POST.get('last_name', '')
        company_name = request.POST.get('company_name', '')
        phone_number = request.POST.get('phone_number', '')
        company_address = request.POST.get('company_address', '')
        company_branch = request.POST.get('company_branch', '')
        device_id = request.POST.get('device_id', 0)
        model_name = request.POST.get('model_name', '')
        model_version = request.POST.get('model_version', '')
        
        # Create context for form preservation
        form_data = {
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'company_name': company_name,
            'phone_number': phone_number,
            'company_address': company_address,
            'company_branch': company_branch,
            'device_id': device_id,
            'model_name': model_name,
            'model_version': model_version
        }
        
        # Validate input
        if not email or not password:
            form_data['error'] = 'Email and password are required.'
            return render(request, 'main/register.html', form_data)
        
        if len(password) < 6:
            form_data['error'] = 'Password must be at least 6 characters long.'
            return render(request, 'main/register.html', form_data)
        
        if User.objects.filter(email=email).exists():
            form_data['error'] = 'An account with this email already exists. Please use a different email or try logging in.'
            # Remove email from form data since it's invalid
            form_data['email'] = ''
            return render(request, 'main/register.html', form_data)
        
        try:
            user = User.objects.create_user(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                company_name=company_name,
                phone_number=phone_number,
                company_address=company_address,
                company_branch=company_branch,
                device_id=int(device_id) if device_id else 0,
                model_name=model_name,
                model_version=model_version
            )
            
            # Don't auto-login since new users need to be activated by admin
            return render(request, 'main/register.html', {
                'success': 'Account created successfully! Your account needs to be activated by an administrator before you can log in. You will be notified once your account is active.'
            })
            
        except Exception as e:
            form_data['error'] = 'There was an error creating your account. Please try again or contact support.'
            return render(request, 'main/register.html', form_data)
    
    return render(request, 'main/register.html')

@login_required
def home(request):
    """Home/Dashboard view"""
    return render(request, 'main/home.html')

@login_required
def admin_dashboard(request):
    """Admin dashboard view"""
    if not request.user.is_superuser:
        return redirect('home')
    return render(request, 'main/adminDashboard.html')

@login_required
def registered_clients(request):
    """View for registered clients (admin only)"""
    if not request.user.is_superuser:
        return redirect('home')
    clients = User.objects.all()
    return render(request, 'main/registeredClients.html', {'clients': clients})

@login_required
def device_status(request, user_id):
    """Device status view - shows complete device and compliance information"""
    user = get_object_or_404(User, pk=user_id)
    if not request.user.is_superuser and request.user != user:
        return redirect('home')
    
    # Check certificate status
    cert_path = os.path.join(settings.BASE_DIR, 'certificates', f'device_cert_{user.id}.pem')
    key_path = os.path.join(settings.BASE_DIR, 'certificates', 'private.key')
    
    cert_status = {
        'certificate_exists': os.path.exists(cert_path),
        'private_key_exists': os.path.exists(key_path),
        'cert_path': cert_path,
        'key_path': key_path
    }
    
    # Get recent receipts for this user
    recent_receipts = Receipt.objects.filter(
        # Note: We'll need to add user relationship to Receipt model
        # For now, we'll show all recent receipts
    ).order_by('-created_at')[:10]
    
    # Get submission statistics
    submission_stats = ReceiptSubmissionLog.objects.aggregate(
        total_submitted=Count('id', filter=Q(submission_status='SUBMITTED')),
        total_failed=Count('id', filter=Q(submission_status='FAILED')),
        total_pending=Count('id', filter=Q(submission_status='PENDING')),
        total_retry=Count('id', filter=Q(submission_status='RETRY'))
    )
    
    # Get recent submission logs
    recent_submissions = ReceiptSubmissionLog.objects.select_related('receipt').order_by('-submission_timestamp')[:5]
    
    # Device configuration status
    device_config = {
        'device_id_set': bool(user.device_id),
        'model_name_set': bool(user.model_name),
        'model_version_set': bool(user.model_version),
        'is_fully_configured': bool(user.device_id and user.model_name and user.model_version)
    }
    
    # Check ZIMRA connection (we'll add this functionality)
    zimra_status = {
        'last_connection': None,  # Will implement
        'connection_status': 'Unknown'  # Will implement
    }
    
    context = {
        'user': user,
        'cert_status': cert_status,
        'recent_receipts': recent_receipts,
        'submission_stats': submission_stats,
        'recent_submissions': recent_submissions,
        'device_config': device_config,
        'zimra_status': zimra_status
    }
    
    return render(request, 'main/clientInfo.html', context)

@login_required
def client_activation(request, user_id):
    """Client activation view"""
    if not request.user.is_superuser:
        return redirect('home')
    
    user = get_object_or_404(User, pk=user_id)
    user.is_active = True
    user.save()
    
    return redirect('client_info', user_id=user.id)

@login_required
def client_deactivation(request, user_id):
    """Client deactivation view"""
    if not request.user.is_superuser:
        return redirect('home')
    
    user = get_object_or_404(User, pk=user_id)
    user.is_active = False
    user.save()
    
    return redirect('client_info', user_id=user.id)

@login_required
def register_new_device(request, user_id):
    """Register new device view"""
    if not request.user.is_superuser:
        return redirect('home')
    
    user = get_object_or_404(User, pk=user_id)
    return render(request, 'main/deviceReg.html', {'client': user})

@login_required
def device_config(request, user_id):
    """Comprehensive Device Configuration Dashboard"""
    user = get_object_or_404(User, pk=user_id)
    if not request.user.is_superuser and request.user != user:
        return redirect('home')
    
    # Initialize context data
    context = {
        'user': user,
        'device_info': {},
        'certificate_status': {},
        'zimra_config': {},
        'health_checks': {},
        'api_endpoints': {},
        'recent_activity': [],
        'error_logs': []
    }
    
    # Get device configuration from ZIMRA
    cert_path = os.path.join(settings.BASE_DIR, 'certificates', f'device_cert_{user.id}.pem')
    key_path = os.path.join(settings.BASE_DIR, 'certificates', 'private.key')
    
    # Check certificate status
    context['certificate_status'] = {
        'cert_exists': os.path.exists(cert_path),
        'key_exists': os.path.exists(key_path),
        'cert_path': cert_path,
        'key_path': key_path,
        'status': 'Valid' if (os.path.exists(cert_path) and os.path.exists(key_path)) else 'Missing'
    }
    
    # Add certificate expiry check if certificate exists
    if os.path.exists(cert_path):
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            import datetime
            
            with open(cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
                
                context['certificate_status'].update({
                    'subject': str(certificate.subject),
                    'issuer': str(certificate.issuer),
                    'valid_from': certificate.not_valid_before_utc.replace(tzinfo=None),
                    'valid_until': certificate.not_valid_after_utc.replace(tzinfo=None),
                    'is_expired': certificate.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc),
                    'days_until_expiry': (certificate.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)).days
                })
        except ImportError:
            context['certificate_status']['parsing_error'] = 'Cryptography library not available'
        except Exception as e:
            context['certificate_status']['parsing_error'] = str(e)
    
    # Device configuration data
    context['device_info'] = {
        'device_id': user.device_id,
        'model_name': user.model_name or 'Not Set',
        'model_version': user.model_version or 'Not Set',
        'company_name': user.company_name,
        'registration_status': 'Active' if user.is_active else 'Inactive',
        'setup_progress': calculate_setup_progress(user),
        # ZIMRA-specific data
        'zimra_serial_number': user.zimra_serial_number or 'Not synced',
        'zimra_firmware_version': user.zimra_firmware_version or 'Not synced',
        'zimra_device_status': user.zimra_device_status or 'Unknown',
        'zimra_device_type': user.zimra_device_type or 'Not synced',
        'zimra_tax_period': user.zimra_tax_period or 'Not synced',
        'zimra_registration_status': user.zimra_registration_status or 'Unknown',
        'zimra_last_receipt_number': user.zimra_last_receipt_number or 'None',
        'zimra_last_sync': user.zimra_last_sync,
        'has_zimra_data': bool(user.zimra_last_sync)
    }
    
    # ZIMRA API endpoints and configuration
    context['api_endpoints'] = {
        'base_url': 'https://fdmsapitest.zimra.co.zw',
        'get_config': f"https://fdmsapitest.zimra.co.zw/Device/v1/{user.device_id}/GetConfiguration",
        'get_status': f"https://fdmsapitest.zimra.co.zw/Device/v1/{user.device_id}/GetStatus",
        'submit_receipt': f"https://fdmsapitest.zimra.co.zw/Receipt/v1/{user.device_id}",
        'environment': 'Test'
    }
    
    # Test ZIMRA connectivity if certificates exist
    if context['certificate_status']['cert_exists'] and context['certificate_status']['key_exists']:
        zimra_status = test_zimra_connectivity(user, cert_path, key_path)
        context['zimra_config'] = zimra_status
    else:
        context['zimra_config'] = {
            'connection_status': 'No Certificates',
            'last_test': 'Never',
            'error': 'Certificates not found'
        }
    
    # Recent submission activity
    recent_submissions = ReceiptSubmissionLog.objects.filter(
        receipt__user=user
    ).order_by('-submission_timestamp')[:10]
    
    context['recent_activity'] = recent_submissions
    
    # Health checks
    context['health_checks'] = {
        'device_configured': bool(user.device_id and user.model_name),
        'certificates_valid': context['certificate_status']['status'] == 'Valid',
        'zimra_connected': context['zimra_config'].get('connection_status') == 'Connected',
        'user_active': user.is_active,
        'overall_status': 'Healthy' if all([
            bool(user.device_id and user.model_name),
            context['certificate_status']['status'] == 'Valid',
            user.is_active
        ]) else 'Issues Detected'
    }
    
    # Handle POST requests for configuration updates
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'update_device_info':
            user.model_name = request.POST.get('model_name', user.model_name)
            user.model_version = request.POST.get('model_version', user.model_version)
            user.device_id = request.POST.get('device_id', user.device_id)
            user.save()
            
            messages.success(request, 'Device information updated successfully!')
            return redirect('device_config', user_id=user.id)
            
        elif action == 'test_connection':
            if context['certificate_status']['cert_exists']:
                test_result = test_zimra_connectivity(user, cert_path, key_path)
                if test_result.get('connection_status') == 'Connected':
                    messages.success(request, 'ZIMRA connection test successful!')
                else:
                    messages.error(request, f"Connection test failed: {test_result.get('error', 'Unknown error')}")
            else:
                messages.error(request, 'Cannot test connection: Certificates not found')
            return redirect('device_config', user_id=user.id)
            
        elif action == 'sync_with_zimra':
            # Implement ZIMRA synchronization
            sync_result = sync_device_with_zimra(user)
            if sync_result['success']:
                updated_fields = sync_result.get('updated_fields', {})
                field_count = sum(1 for v in updated_fields.values() if v and v != 'Not synced' and v != 'Unknown')
                if field_count > 0:
                    messages.success(request, f'Device synchronized with ZIMRA successfully! Updated {field_count} fields from ZIMRA servers.')
                else:
                    messages.info(request, 'Synchronized with ZIMRA, but no new data was available.')
                
                if sync_result.get('errors'):
                    for error in sync_result['errors']:
                        messages.warning(request, f"Partial sync issue: {error}")
            else:
                messages.error(request, f"Synchronization failed: {sync_result.get('error')}")
            return redirect('device_config', user_id=user.id)
    
    return render(request, 'main/device_config.html', context)

def calculate_setup_progress(user):
    """Calculate device setup completion percentage"""
    completed_steps = 0
    total_steps = 6  # Increased to include ZIMRA sync
    
    if user.device_id:
        completed_steps += 1
    if user.model_name:
        completed_steps += 1
    if user.is_active:
        completed_steps += 1
    
    cert_path = os.path.join(settings.BASE_DIR, 'certificates', f'device_cert_{user.id}.pem')
    if os.path.exists(cert_path):
        completed_steps += 1
    
    # Check if user has made any receipts
    if Receipt.objects.filter(user=user).exists():
        completed_steps += 1
    
    # Check if ZIMRA data has been synced
    if user.zimra_last_sync:
        completed_steps += 1
    
    return int((completed_steps / total_steps) * 100)

def test_zimra_connectivity(user, cert_path, key_path):
    """Test connectivity to ZIMRA API"""
    try:
        url = f"https://fdmsapitest.zimra.co.zw/Device/v1/{user.device_id}/GetStatus"
        headers = {
            "Content-Type": "application/json",
            "DeviceModelName": user.model_name or "DefaultModel",
            "DeviceModelVersion": user.model_version or "1.0"
        }
        
        # Try alternative endpoints for better compatibility
        urls_to_try = [
            f"https://fdmsapitest.zimra.co.zw/Device/v1/{user.device_id}/GetStatus",
            f"https://fdmsapitest.zimra.co.zw/Device/v1/{user.device_id}/GetConfiguration",
            f"https://fdmsapitest.zimra.co.zw/api/v1/device/{user.device_id}/status"
        ]
        
        last_response = None
        for test_url in urls_to_try:
            try:
                response = requests.get(test_url, cert=(cert_path, key_path), headers=headers, verify=False, timeout=30)
                last_response = response
                
                print(f"Testing URL: {test_url}")
                print(f"Status: {response.status_code}")
                print(f"Response: {response.text[:200]}...")
                
                if response.status_code == 200:
                    return {
                        'connection_status': 'Connected',
                        'last_test': timezone.now(),
                        'response_time': response.elapsed.total_seconds(),
                        'zimra_response': response.json(),
                        'successful_url': test_url
                    }
            except Exception as e:
                print(f"URL {test_url} failed: {e}")
                continue
        
        # If we get here, all URLs failed
        response = last_response
        if response:
            return {
                'connection_status': 'Error',
                'last_test': timezone.now(),
                'error': f"HTTP {response.status_code}: {response.text}",
                'response_time': response.elapsed.total_seconds()
            }
        else:
            return {
                'connection_status': 'Failed',
                'last_test': timezone.now(),
                'error': "All API endpoints failed",
                'response_time': None
            }
            
    except requests.exceptions.RequestException as e:
        return {
            'connection_status': 'Failed',
            'last_test': timezone.now(),
            'error': str(e),
            'response_time': None
        }

def sync_device_with_zimra(user):
    """Synchronize device configuration with ZIMRA"""
    cert_path = os.path.join(settings.BASE_DIR, 'certificates', f'device_cert_{user.id}.pem')
    key_path = os.path.join(settings.BASE_DIR, 'certificates', 'private.key')
    
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        return {'success': False, 'error': 'Certificates not found'}
    
    try:
        # Get current configuration from ZIMRA
        config_url = f"https://fdmsapitest.zimra.co.zw/Device/v1/{user.device_id}/GetConfiguration"
        status_url = f"https://fdmsapitest.zimra.co.zw/Device/v1/{user.device_id}/GetStatus"
        headers = {
            "Content-Type": "application/json",
            "DeviceModelName": user.model_name or "DefaultModel",
            "DeviceModelVersion": user.model_version or "1.0"
        }
        
        # Get both configuration and status from ZIMRA (disable SSL verification for test environment)
        config_response = requests.get(config_url, cert=(cert_path, key_path), headers=headers, verify=False, timeout=30)
        status_response = requests.get(status_url, cert=(cert_path, key_path), headers=headers, verify=False, timeout=30)
        
        success = True
        zimra_data = {}
        error_messages = []
        
        # Process configuration response
        if config_response.status_code == 200:
            config_data = config_response.json()
            zimra_data['configuration'] = config_data
            
            # Update user fields with ZIMRA configuration data
            if 'serialNumber' in config_data:
                user.zimra_serial_number = config_data['serialNumber']
            if 'firmwareVersion' in config_data:
                user.zimra_firmware_version = config_data['firmwareVersion']
            if 'deviceType' in config_data:
                user.zimra_device_type = config_data['deviceType']
            if 'taxPeriod' in config_data:
                user.zimra_tax_period = config_data['taxPeriod']
            if 'modelName' in config_data and not user.model_name:
                user.model_name = config_data['modelName']
            if 'modelVersion' in config_data and not user.model_version:
                user.model_version = config_data['modelVersion']
                
        else:
            error_messages.append(f"Config API returned HTTP {config_response.status_code}")
            success = False
        
        # Process status response
        if status_response.status_code == 200:
            status_data = status_response.json()
            zimra_data['status'] = status_data
            
            # Update user fields with ZIMRA status data
            if 'deviceStatus' in status_data:
                user.zimra_device_status = status_data['deviceStatus']
            if 'registrationStatus' in status_data:
                user.zimra_registration_status = status_data['registrationStatus']
            if 'lastReceiptNumber' in status_data:
                user.zimra_last_receipt_number = status_data['lastReceiptNumber']
                
        else:
            error_messages.append(f"Status API returned HTTP {status_response.status_code}")
            
        # Store complete ZIMRA response data
        user.zimra_response_data = zimra_data
        user.zimra_last_sync = timezone.now()
        user.save()
        
        return {
            'success': success,
            'zimra_data': zimra_data,
            'sync_time': timezone.now(),
            'errors': error_messages if error_messages else None,
            'updated_fields': {
                'serial_number': user.zimra_serial_number,
                'firmware_version': user.zimra_firmware_version,
                'device_status': user.zimra_device_status,
                'registration_status': user.zimra_registration_status,
                'device_type': user.zimra_device_type,
                'tax_period': user.zimra_tax_period,
                'last_receipt_number': user.zimra_last_receipt_number
            }
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

@login_required
def confirm_device_reg(request, user_id):
    """Confirm device registration view"""
    if not request.user.is_superuser:
        return redirect('home')
    
    user = get_object_or_404(User, pk=user_id)
    
    if request.method == 'POST':
        # Handle device registration confirmation logic here
        # This could involve calling the CSR registration API
        pass
    
    return render(request, 'main/deviceReg.html', {'client': user})

@login_required
def submit_receipt_view(request):
    """Submit receipt view"""
    return render(request, 'main/submitReceipt.html')

@login_required
def submit_invoice_view(request):
    """Submit invoice view"""
    return render(request, 'main/invoice.html')

@login_required
def open_fiscal_day(request):
    """Open fiscal day view"""
    return render(request, 'main/openFiscalDay.html')

@login_required
def close_fiscal_day(request):
    """Close fiscal day view"""
    return render(request, 'main/closeFiscalDay.html')

@login_required
def profile(request):
    """User profile view"""
    return render(request, 'main/profile.html')

@login_required
def zimra_dashboard(request):
    """ZIMRA compliance dashboard"""
    if not request.user.is_superuser:
        return redirect('home')
    
    # Get submission statistics
    stats = ReceiptSubmissionLog.objects.aggregate(
        submitted=Count('id', filter=Q(submission_status='SUBMITTED')),
        pending=Count('id', filter=Q(submission_status='PENDING')),
        failed=Count('id', filter=Q(submission_status='FAILED')),
        retry=Count('id', filter=Q(submission_status='RETRY'))
    )
    
    # Get recent submission logs
    recent_logs = ReceiptSubmissionLog.objects.select_related('receipt').order_by('-submission_timestamp')[:20]
    
    context = {
        'stats': stats,
        'recent_logs': recent_logs
    }
    
    return render(request, 'main/zimra_dashboard.html', context)

@login_required
def change_password_view(request):
    """Change password view"""
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            return redirect('profile')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'main/changePassword.html', {'form': form})

def logout_view(request):
    """Logout view"""
    logout(request)
    return redirect('home')