from django.db import models
from django.db.models import F, ExpressionWrapper
from django.contrib.auth.models import UserManager, AbstractBaseUser, PermissionsMixin
import datetime
from django.utils import timezone


current_date = datetime.date.today()

# Create your models here.
class FiscalDay(models.Model):
    day_opened = models.DateField(auto_now_add=True)
    day_number = models.IntegerField(default=0)
    
    
    def __str__(self):
        return str(self.day_number)
    
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
    first_name = models.CharField(max_length=255, blank=True, default='')
    last_name = models.CharField(max_length=255, blank=True, default='')
    phone_number = models.CharField(max_length=20, blank=True, default='')
    company_name = models.CharField(max_length=255, blank=True, default='')
    company_address  = models.CharField(max_length=255, blank=True, default='')
    company_branch = models.CharField(max_length=255, blank=True, default='')
    device_id = models.IntegerField(default=0, blank=True)
    model_name = models.CharField(max_length=255, blank=True, default='')
    model_version = models.CharField(max_length=255, blank=True, default='')
    activation_key = models.CharField(max_length=30, blank=True, null=True)
    
    is_subscribed = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    fiscal_days = models.ForeignKey(FiscalDay,
                             null=True,
                             on_delete=models.SET_NULL, blank=True)
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

class Buyer(models.Model):
    reg_name = models.CharField(max_length=255, blank =True, null=True)
    trade_name = models.CharField(max_length=255, blank=True, null=True)
    tin = models.CharField(max_length=255, blank=True, null=True)
    vat_number = models.CharField(max_length=255, blank=True, null=True)
    contacts = models.CharField(max_length=255, blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.trade_name or self.reg_name or f"Buyer {self.pk}"

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
        super().save(*args, **kwargs)

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