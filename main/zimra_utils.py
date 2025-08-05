"""
ZIMRA FDMS Integration Utilities
Handles automatic submission and compliance monitoring
"""
import os
import requests
import logging
from django.conf import settings
from .models import Receipt, ReceiptSubmissionLog

logger = logging.getLogger(__name__)

class ZIMRAIntegration:
    """Utility class for ZIMRA FDMS integration"""
    
    def __init__(self):
        self.base_url = "https://fdmsapitest.zimra.co.zw/Device/v1"
    
    def auto_submit_receipt(self, receipt_id, user):
        """
        Automatically submit receipt to ZIMRA when created
        Called from receipt creation process
        """
        try:
            receipt = Receipt.objects.get(id=receipt_id)
            
            # Check if already submitted
            existing_log = ReceiptSubmissionLog.objects.filter(
                receipt=receipt,
                submission_status='SUBMITTED'
            ).first()
            
            if existing_log:
                logger.info(f"Receipt {receipt.invoice_number} already submitted to ZIMRA")
                return True
            
            # Validate prerequisites
            if not self._validate_device_setup(user):
                logger.error(f"Device setup invalid for user {user.id}")
                return False
            
            # Prepare submission data
            submission_data = self._prepare_receipt_data(receipt)
            
            # Create submission log
            submission_log = ReceiptSubmissionLog.objects.create(
                receipt=receipt,
                submission_status='PENDING'
            )
            
            # Submit to ZIMRA
            success = self._submit_to_zimra(submission_data, user, submission_log)
            
            return success
            
        except Receipt.DoesNotExist:
            logger.error(f"Receipt {receipt_id} not found for auto-submission")
            return False
        except Exception as e:
            logger.error(f"Error in auto_submit_receipt: {str(e)}")
            return False
    
    def _validate_device_setup(self, user):
        """Validate user device configuration"""
        cert_path = os.path.join(settings.BASE_DIR, 'certificates', f'device_cert_{user.id}.pem')
        key_path = os.path.join(settings.BASE_DIR, 'certificates', 'private.key')
        
        checks = [
            os.path.exists(cert_path),
            os.path.exists(key_path),
            bool(user.device_id),
            bool(user.model_name),
            bool(user.model_version),
            user.is_active
        ]
        
        return all(checks)
    
    def _prepare_receipt_data(self, receipt):
        """Prepare receipt data for ZIMRA submission"""
        # Format receipt data according to ZIMRA FDMS specification
        receipt_data = {
            "receiptType": receipt.receipt_type,
            "receiptCurrency": receipt.currency,
            "receiptCounter": receipt.counter,
            "receiptGlobalNo": receipt.global_number,
            "invoiceNo": receipt.invoice_number,
            "receiptDate": receipt.date.isoformat() if receipt.date else "",
            "receiptTotal": float(receipt.total),
            "taxInclusive": receipt.tax_inclusive,
            "receiptHash": receipt.hash_val,
            "receiptNotes": receipt.receipt_notes or "",
        }
        
        # Add buyer information if available
        if receipt.buyer:
            receipt_data["buyer"] = {
                "buyerRegisterName": receipt.buyer.reg_name or "",
                "buyerTradeName": receipt.buyer.trade_name or "",
                "buyerTIN": receipt.buyer.tin or "",
                "vatNumber": receipt.buyer.vat_number or "",
                "buyerContacts": receipt.buyer.contacts or "",
                "buyerAddress": receipt.buyer.address or "",
            }
        
        # Add receipt lines
        receipt_data["receiptLines"] = []
        for line in receipt.receipt_lines.all():
            line_data = {
                "receiptLineType": line.line_type,
                "receiptLineNo": line.line_number,
                "receiptLineHSCode": line.line_hs_code or "",
                "receiptLineName": line.line_name,
                "receiptLinePrice": line.line_price,
                "receiptLineQuantity": line.line_quantity,
                "receiptLineTotal": line.line_total,
                "taxCode": line.line_taxcode or "",
                "taxPercent": line.tax_percent or 0,
                "taxID": line.tax_id or 0,
            }
            receipt_data["receiptLines"].append(line_data)
        
        # Add receipt taxes
        receipt_data["receiptTaxes"] = []
        for tax in receipt.receipt_taxes.all():
            tax_data = {
                "taxCode": tax.taxCode or "",
                "taxPercent": float(tax.taxPercent or 0),
                "taxID": tax.taxID or 0,
                "taxAmount": float(tax.taxAmount or 0),
                "salesAmountWithTax": float(tax.salesAmountWithTax or 0),
            }
            receipt_data["receiptTaxes"].append(tax_data)
        
        # Add payment information
        receipt_data["receiptPayments"] = [{
            "moneyTypeCode": receipt.payment_moneyTypeCode or "Cash",
            "paymentAmount": receipt.paymentPaymentAmount,
        }]
        
        return receipt_data
    
    def _submit_to_zimra(self, receipt_data, user, submission_log):
        """Submit receipt data to ZIMRA"""
        url = f"{self.base_url}/{user.device_id}/SubmitReceipt"
        cert_path = os.path.join(settings.BASE_DIR, 'certificates', f'device_cert_{user.id}.pem')
        key_path = os.path.join(settings.BASE_DIR, 'certificates', 'private.key')
        
        headers = {
            'Content-Type': 'application/json',
            "DeviceModelName": user.model_name,
            "DeviceModelVersion": user.model_version,
        }
        
        try:
            response = requests.post(
                url, 
                json=receipt_data, 
                cert=(cert_path, key_path), 
                headers=headers, 
                verify=True, 
                timeout=30
            )
            response.raise_for_status()
            
            # Update submission log on success
            submission_log.submission_status = 'SUBMITTED'
            submission_log.zimra_response = response.text
            submission_log.zimra_receipt_number = response.json().get('receiptNumber', '')
            submission_log.save()
            
            logger.info(f"Successfully submitted receipt {receipt_data['invoiceNo']} to ZIMRA")
            return True
            
        except requests.exceptions.RequestException as e:
            # Update submission log on failure
            submission_log.submission_status = 'FAILED'
            submission_log.error_message = str(e)
            submission_log.retry_count += 1
            submission_log.save()
            
            logger.error(f"Failed to submit receipt {receipt_data['invoiceNo']} to ZIMRA: {str(e)}")
            return False
    
    def retry_failed_submissions(self, max_retries=3):
        """Retry failed receipt submissions"""
        failed_logs = ReceiptSubmissionLog.objects.filter(
            submission_status__in=['FAILED', 'RETRY'],
            retry_count__lt=max_retries
        )
        
        retry_results = []
        for log in failed_logs:
            logger.info(f"Retrying submission for receipt {log.receipt.invoice_number}")
            
            # Get the user associated with the receipt
            user = log.receipt.buyer  # Assuming buyer has user relationship
            if not user:
                logger.error(f"No user found for receipt {log.receipt.invoice_number}")
                continue
            
            success = self.auto_submit_receipt(log.receipt.id, user)
            retry_results.append({
                'receipt': log.receipt.invoice_number,
                'success': success
            })
        
        return retry_results

# Global instance for easy access
zimra_integration = ZIMRAIntegration()
