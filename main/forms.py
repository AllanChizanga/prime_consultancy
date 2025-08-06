from django import forms
from .models import Receipt, ReceiptLine, ReceiptTax, User

class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'phone_number', 'company_name']  # Include the fields you want to update
        widgets = {
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'company_name': forms.TextInput(attrs={'class': 'form-control'}),
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control'}),
            
        }
        

from django import forms
from .models import Receipt, ReceiptLine, ReceiptTax, Buyer

class BuyerForm(forms.ModelForm):
    class Meta:
        model = Buyer
        fields = [
            'reg_name', 'trade_name', 'vat_number', 'bp_number',
            'phone', 'contactPersonName', 'email', 'province', 
            'city', 'district', 'street', 'house_number'
        ]

class ReceiptForm(forms.ModelForm):
    class Meta:
        model = Receipt
        fields = [
            'receipt_type', 'currency', 'invoice_number', 'receipt_notes', 
            'payment_moneyTypeCode', 'paymentPaymentAmount', 'tax_inclusive'
        ]
        widgets = {
            'receipt_type': forms.Select(attrs={'class': 'form-control'}),
            'currency': forms.Select(attrs={'class': 'form-control'}),
            'invoice_number': forms.TextInput(attrs={
                'class': 'form-control', 
                'placeholder': 'Leave blank for auto-generation'
            }),
            'receipt_notes': forms.Textarea(attrs={
                'class': 'form-control', 
                'rows': 3,
                'placeholder': 'Optional notes about this receipt'
            }),
            'payment_moneyTypeCode': forms.Select(attrs={'class': 'form-control'}),
            'paymentPaymentAmount': forms.NumberInput(attrs={
                'class': 'form-control', 
                'step': '0.01',
                'placeholder': '0.00'
            }),
            'tax_inclusive': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }
        labels = {
            'receipt_type': 'Receipt Type',
            'currency': 'Currency',
            'invoice_number': 'Invoice Number',
            'receipt_notes': 'Notes',
            'payment_moneyTypeCode': 'Payment Method',
            'paymentPaymentAmount': 'Payment Amount',
            'tax_inclusive': 'Prices Include Tax',
        }
        help_texts = {
            'invoice_number': 'Leave blank to auto-generate based on sequence',
            'tax_inclusive': 'Check if the entered prices already include tax',
            'payment_moneyTypeCode': 'How was this payment made? (Cash, Card, etc.)',
            'paymentPaymentAmount': 'Total amount paid by customer',
        }

class ReceiptLineForm(forms.ModelForm):
    class Meta:
        model = ReceiptLine
        fields = [
            'line_type', 'line_name', 'line_price', 'line_quantity', 
            'line_hs_code', 'line_taxcode', 'tax_percent', 'tax_id'
        ]
        widgets = {
            'line_type': forms.Select(attrs={'class': 'form-control'}),
            'line_name': forms.TextInput(attrs={
                'class': 'form-control', 
                'placeholder': 'Item or service name'
            }),
            'line_price': forms.NumberInput(attrs={
                'class': 'form-control', 
                'step': '0.01',
                'placeholder': '0.00'
            }),
            'line_quantity': forms.NumberInput(attrs={
                'class': 'form-control', 
                'step': '0.01',
                'value': '1',
                'placeholder': '1'
            }),
            'line_hs_code': forms.TextInput(attrs={
                'class': 'form-control', 
                'placeholder': 'HS Code (optional)'
            }),
            'line_taxcode': forms.TextInput(attrs={
                'class': 'form-control', 
                'placeholder': 'Tax code'
            }),
            'tax_percent': forms.NumberInput(attrs={
                'class': 'form-control', 
                'step': '0.01',
                'placeholder': '15.00'
            }),
            'tax_id': forms.TextInput(attrs={
                'class': 'form-control', 
                'placeholder': 'Tax ID'
            }),
        }

class ReceiptTaxForm(forms.ModelForm):
    class Meta:
        model = ReceiptTax
        fields = [
            'taxCode', 'taxPercent', 'taxID', 
            'taxAmount', 'salesAmountWithTax'
        ]
        widgets = {
            'taxCode': forms.TextInput(attrs={
                'class': 'form-control', 
                'placeholder': 'VAT'
            }),
            'taxPercent': forms.NumberInput(attrs={
                'class': 'form-control', 
                'step': '0.01',
                'placeholder': '15.00'
            }),
            'taxID': forms.TextInput(attrs={
                'class': 'form-control', 
                'placeholder': 'Tax ID'
            }),
            'taxAmount': forms.NumberInput(attrs={
                'class': 'form-control', 
                'step': '0.01',
                'placeholder': '0.00',
                'readonly': True
            }),
            'salesAmountWithTax': forms.NumberInput(attrs={
                'class': 'form-control', 
                'step': '0.01',
                'placeholder': '0.00'
            }),
        }
        labels = {
            'taxCode': 'Tax Code',
            'taxPercent': 'Tax %',
            'taxID': 'Tax ID',
            'taxAmount': 'Tax Amount',
            'salesAmountWithTax': 'Sales Amount With Tax',
        }
        help_texts = {
            'taxCode': 'Type of tax (e.g., VAT, GST)',
            'taxPercent': 'Tax percentage rate',
            'taxID': 'Tax identification number',
            'taxAmount': 'Calculated automatically',
            'salesAmountWithTax': 'Total sales amount including tax',
        }
