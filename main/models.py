from django.db import models
from django.db.models import F, ExpressionWrapper
from django.contrib.auth.models import UserManager, AbstractBaseUser, PermissionsMixin
from django.utils import timezone
from django.conf import settings
import datetime
import hashlib
import json
import os
import uuid

current_date = datetime.date.today()

class Buyer(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    reg_name = models.CharField(max_length=100)
    trade_name = models.CharField(max_length=100, blank=True, null=True)
    vat_number = models.CharField(max_length=50, blank=True, null=True)
    bp_number = models.CharField(max_length=100, blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    contactPersonName = models.CharField(max_length=100, blank=True, null=True)
    province = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    district = models.CharField(max_length=100, blank=True, null=True)
    street = models.CharField(max_length=100, blank=True, null=True)
    house_number = models.CharField(max_length=10, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    
    def __str__(self):
        return self.reg_name

# Create your models here.
class FiscalDay(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='fiscal_days')
    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    date_opened = models.DateTimeField(auto_now_add=True)
    date_closed = models.DateTimeField(null=True, blank=True)
    day_number = models.IntegerField()
    
    def __str__(self):
        return f"Fiscal Day {self.day_number} for {self.user.username}"
    
    @property
    def is_open(self):
        return self.date_closed is None
    
    @property
    def duration(self):
        if self.date_closed:
            return (self.date_closed.date() - self.date_opened.date()).days
        return (timezone.now().date() - self.date_opened.date()).days
    
class CustomUserManager(UserManager):
    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("You have not provided an email")
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using = self.db)
        
        return user
    
    def create_user(self, email=None, password = None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        
        return self._create_user(email, password, **extra_fields)
    
    def create_superuser(self, email=None, password = None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        return self._create_user(email, password, **extra_fields)
    
class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, default='', blank=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    first_name = models.CharField(max_length=255, blank=True, default='')
    last_name = models.CharField(max_length=255, blank=True, default='')
    phone_number = models.CharField(max_length=20, blank=True, default='')
    company_name = models.CharField(max_length=255, blank=True, default='')
    company_address  = models.CharField(max_length=255, blank=True, default='')
    company_branch = models.CharField(max_length=255, blank=True, default='')
    tax_number = models.CharField(max_length=50, blank=True, default='')
    device_id = models.IntegerField(default=0, blank=True)
    model_name = models.CharField(max_length=255, blank=True, default='')
    model_version = models.CharField(max_length=255, blank=True, default='')
    activation_key = models.CharField(max_length=30, blank=True, null=True)
    
    # ZIMRA-specific fields
    zimra_device_status = models.CharField(max_length=50, blank=True, default='')
    zimra_last_sync = models.DateTimeField(null=True, blank=True)
    zimra_serial_number = models.CharField(max_length=100, blank=True, default='')
    zimra_firmware_version = models.CharField(max_length=50, blank=True, default='')
    zimra_tax_period = models.CharField(max_length=50, blank=True, default='')
    zimra_device_type = models.CharField(max_length=50, blank=True, default='')
    zimra_registration_status = models.CharField(max_length=50, blank=True, default='')
    zimra_last_receipt_number = models.CharField(max_length=50, blank=True, default='')
    zimra_response_data = models.JSONField(default=dict, blank=True)
    
    is_subscribed = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    
    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    def __str__(self):
        return self.company_name
    
    class Meta:
        verbose_name = 'Client'
        verbose_name_plural = 'Clients'
        
class Csr(models.Model):
    mycsr = models.TextField()
    mykey = models.TextField()
    
    def __str__(self):
        return f"CSR {self.pk}"
    

RECEIPT_LINE_TYPE = (
    ('Sales', 'Sales'),
    ('Discount', 'Discount'),
)

class ReceiptTax(models.Model):
    receipt = models.ForeignKey('Receipt', on_delete=models.CASCADE, related_name='receipt_taxes')
    taxCode = models.CharField(max_length=20, blank =True, null=True)
    taxPercent = models.DecimalField(max_digits=5, decimal_places=2, default=0, blank=True, null=True)
    taxID = models.IntegerField(blank =True, null=True)
    taxAmount = models.DecimalField(max_digits=5, decimal_places=2, default=0, blank=True, null=True)
    salesAmountWithTax = models.DecimalField(max_digits=5, decimal_places=2, default=0, blank=True, null=True)

    def __str__(self):
        return f"Tax {self.taxCode} - {self.taxPercent}%"

class ReceiptLine(models.Model):
    receipt = models.ForeignKey('Receipt', on_delete=models.CASCADE, related_name='receipt_lines')
    line_type = models.CharField(max_length=20, null=True, choices=RECEIPT_LINE_TYPE)
    line_number = models.IntegerField(default=0)
    line_hs_code = models.CharField(max_length=20, blank =True, null=True)
    line_name = models.CharField(max_length=255)
    line_price = models.FloatField()
    line_quantity = models.FloatField()
    line_total = models.FloatField(default=0)
    line_taxcode = models.CharField(max_length=10, blank =True, null=True)
    tax_percent = models.FloatField(default=0, blank =True, null=True)
    tax_id = models.IntegerField(blank =True, null=True)

    def __str__(self):
        return f"{self.line_name} - Qty: {self.line_quantity} @ ${self.line_price}"

class CreditDebitNote(models.Model):
    receipt_id = models.BigIntegerField(blank=True, null=True)
    device_id = models.IntegerField(blank=True, null=True)
    receipt_global_number = models.IntegerField(blank=True, null=True)
    fiscal_day_number = models.IntegerField(blank=True, null=True)

    def __str__(self):
        return f"Credit/Debit Note - Receipt {self.receipt_id}"

RECEIPT_TYPE = (
    ('FiscalInvoice', 'FiscalInvoice'),
    ('DebitNote', 'DebitNote'),
    ('CreditNote', 'CreditNote'),
)

RECEIPT_CURRENCY = (
    ('USD', 'USD'),
    ('ZWL', 'ZWL'),
)
MONEY_TYPE = (
    ('Cash', 'Cash'),
    ('Card', 'Card'),
    ('Moblie Wallet', 'Moblie Wallet'),
    ('Coupon', 'Coupon'),
    ('Credit', 'Credit'),
    ('Bank Transfer', 'Bank Transfer'),
    ('Other', 'Other'),
)

class Receipt(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='receipts', null=True, blank=True)
    buyer = models.ForeignKey(Buyer, on_delete=models.CASCADE, related_name='receipts', blank=True, null=True)
    receipt_type = models.CharField(max_length=20, null=True, choices=RECEIPT_TYPE)
    currency = models.CharField(max_length=20, null=True, choices=RECEIPT_CURRENCY)
    counter = models.IntegerField(default=0)
    global_number = models.IntegerField(default=0)
    invoice_number = models.CharField(max_length=255)
    receipt_notes = models.CharField(default='',max_length=255, blank =True, null=True)
    date = models.DateField(auto_now_add=True)
    tax_inclusive = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # payment
    payment_moneyTypeCode = models.CharField(max_length=20, null=True, choices=MONEY_TYPE)
    paymentPaymentAmount = models.FloatField(default=0)
    
    total = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    hash_val = models.TextField(blank=True, null = True)
    
    def save(self, *args, **kwargs):
        if not self.invoice_number:
             today = timezone.now().date()
        
        if not self.pk:  # Only perform this logic if it's a new receipt
            # Check the last receipt created today
            last_receipt = Receipt.objects.filter(date=today).order_by('-counter').first()
            if last_receipt:
                # Increment counter by 1 from the last receipt of the day
                self.counter = last_receipt.counter + 1
            else:
                # Start counter at 1 if it's a new day or no receipts exist for today
                self.counter = 1
                
            self.invoice_number = self.generate_invoice_number()
            last_receipt = Receipt.objects.order_by('-global_number').first()
            self.global_number = last_receipt.global_number + 1 if last_receipt else 1
            
        # Generate ZIMRA-compliant hash
        if not self.hash_val:
            self.hash_val = self.generate_zimra_hash()
            
        super().save(*args, **kwargs)

    def generate_zimra_hash(self):
        """Generate ZIMRA-compliant receipt hash for fiscal compliance"""
        # Create hash data including all receipt information
        hash_data = {
            'global_number': self.global_number,
            'counter': self.counter,
            'invoice_number': self.invoice_number,
            'date': self.date.isoformat() if self.date else '',
            'total': str(self.total),
            'currency': self.currency,
            'receipt_type': self.receipt_type,
            'tax_inclusive': self.tax_inclusive,
            'payment_amount': self.paymentPaymentAmount,
            'payment_type': self.payment_moneyTypeCode,
        }
        
        # Add buyer information if available
        if self.buyer:
            hash_data.update({
                'buyer_vat': self.buyer.vat_number or '',
                'buyer_name': self.buyer.trade_name or self.buyer.reg_name or '',
                'buyer_bp': self.buyer.bp_number or ''
            })
        
        # Create deterministic JSON string
        hash_string = json.dumps(hash_data, sort_keys=True, separators=(',', ':'))
        
        # Generate SHA-256 hash
        return hashlib.sha256(hash_string.encode('utf-8')).hexdigest()

    def verify_hash(self):
        """Verify the receipt hash for integrity checking"""
        current_hash = self.hash_val
        calculated_hash = self.generate_zimra_hash()
        return current_hash == calculated_hash

    def generate_invoice_number(self):
        prefix = "INV"
        last_invoice = Receipt.objects.all().order_by('-created_at').first()
        if last_invoice:
            last_number = int(last_invoice.invoice_number.split("-")[-1])
            new_number = last_number + 1
        else:
            new_number = 1
        return f"{prefix}-{new_number:05d}"  # Example: INV-00001

    def __str__(self):
        return f"{self.invoice_number} - {self.receipt_type} (${self.total})"

class ReceiptSubmissionLog(models.Model):
    """Track ZIMRA submission status for compliance monitoring"""
    SUBMISSION_STATUS_CHOICES = [
        ('PENDING', 'Pending Submission'),
        ('SUBMITTED', 'Successfully Submitted'),
        ('FAILED', 'Submission Failed'),
        ('RETRY', 'Queued for Retry'),
    ]
    
    receipt = models.ForeignKey(Receipt, on_delete=models.CASCADE, related_name='submission_logs')
    submission_status = models.CharField(max_length=20, choices=SUBMISSION_STATUS_CHOICES, default='PENDING')
    zimra_response = models.TextField(blank=True, null=True)
    submission_timestamp = models.DateTimeField(auto_now_add=True)
    retry_count = models.IntegerField(default=0)
    error_message = models.TextField(blank=True, null=True)
    zimra_receipt_number = models.CharField(max_length=255, blank=True, null=True)
    
    def __str__(self):
        return f"{self.receipt.invoice_number} - {self.submission_status}"
    
    class Meta:
        ordering = ['-submission_timestamp']