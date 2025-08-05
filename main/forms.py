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
            'reg_name', 'trade_name', 'tin', 
            'vat_number', 'contacts', 'address'
        ]

class ReceiptForm(forms.ModelForm):
    class Meta:
        model = Receipt
        fields = [
            'receipt_type', 'currency', 'receipt_notes', 'payment_moneyTypeCode','tax_inclusive'
        ]

class ReceiptLineForm(forms.ModelForm):
    class Meta:
        model = ReceiptLine
        fields = [
            'line_type', 'line_number', 'line_hs_code', 
            'line_name', 'line_price', 'line_quantity', 
            'line_taxcode', 'tax_percent', 'tax_id'
        ]

class ReceiptTaxForm(forms.ModelForm):
    class Meta:
        model = ReceiptTax
        fields = [
            'taxCode', 'taxPercent', 'taxID', 
            'taxAmount', 'salesAmountWithTax'
        ]
