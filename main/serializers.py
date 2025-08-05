from rest_framework import serializers
from .models import User, FiscalDay, Receipt, ReceiptLine, ReceiptTax, Buyer, CreditDebitNote, Csr, ReceiptSubmissionLog

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'phone_number', 
                 'company_name', 'company_address', 'company_branch', 
                 'device_id', 'model_name', 'model_version', 'is_active']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class FiscalDaySerializer(serializers.ModelSerializer):
    class Meta:
        model = FiscalDay
        fields = '__all__'

class BuyerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Buyer
        fields = ['id', 'reg_name', 'trade_name', 'tin', 'vat_number', 'contacts', 'address']

class ReceiptTaxSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReceiptTax
        fields = ['id', 'taxCode', 'taxPercent', 'taxID', 'taxAmount', 'salesAmountWithTax']

class ReceiptLineSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReceiptLine
        fields = ['id', 'line_type', 'line_number', 'line_hs_code', 'line_name', 
                 'line_price', 'line_quantity', 'line_total', 'line_taxcode', 
                 'tax_percent', 'tax_id']

class ReceiptSerializer(serializers.ModelSerializer):
    receipt_lines = ReceiptLineSerializer(many=True, read_only=True)
    receipt_taxes = ReceiptTaxSerializer(many=True, read_only=True)
    buyer = BuyerSerializer()

    class Meta:
        model = Receipt
        fields = ['id', 'buyer', 'receipt_type', 'currency', 'counter', 'global_number',
                 'invoice_number', 'receipt_notes', 'date', 'tax_inclusive', 'created_at',
                 'payment_moneyTypeCode', 'paymentPaymentAmount', 'total', 'hash_val',
                 'receipt_lines', 'receipt_taxes']
        read_only_fields = ['invoice_number', 'counter', 'global_number', 'created_at']

    def create(self, validated_data):
        buyer_data = validated_data.pop('buyer')
        buyer = Buyer.objects.create(**buyer_data)
        receipt = Receipt.objects.create(buyer=buyer, **validated_data)
        return receipt

class CreditDebitNoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = CreditDebitNote
        fields = ['id', 'receipt_id', 'device_id', 'receipt_global_number', 'fiscal_day_number']

class CsrSerializer(serializers.ModelSerializer):
    class Meta:
        model = Csr
        fields = '__all__'

class ReceiptSubmissionLogSerializer(serializers.ModelSerializer):
    receipt = ReceiptSerializer(read_only=True)
    
    class Meta:
        model = ReceiptSubmissionLog
        fields = ['id', 'receipt', 'submission_status', 'zimra_response', 
                 'submission_timestamp', 'retry_count', 'error_message', 
                 'zimra_receipt_number']
        read_only_fields = ['submission_timestamp']
