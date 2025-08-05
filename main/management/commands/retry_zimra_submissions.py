"""
Django management command to retry failed ZIMRA submissions
Usage: python manage.py retry_zimra_submissions
"""
from django.core.management.base import BaseCommand
from main.zimra_utils import zimra_integration
from main.models import ReceiptSubmissionLog

class Command(BaseCommand):
    help = 'Retry failed ZIMRA receipt submissions'

    def add_arguments(self, parser):
        parser.add_argument(
            '--max-retries',
            type=int,
            default=3,
            help='Maximum number of retry attempts (default: 3)',
        )
        parser.add_argument(
            '--receipt-id',
            type=int,
            help='Retry specific receipt by ID',
        )

    def handle(self, *args, **options):
        max_retries = options['max_retries']
        receipt_id = options.get('receipt_id')

        self.stdout.write('Starting ZIMRA submission retry process...')

        if receipt_id:
            # Retry specific receipt
            try:
                log = ReceiptSubmissionLog.objects.get(receipt_id=receipt_id)
                if log.submission_status in ['FAILED', 'RETRY']:
                    # Get user from receipt (you may need to adjust this based on your model relationships)
                    user = getattr(log.receipt, 'user', None)  # Adjust as needed
                    if user:
                        success = zimra_integration.auto_submit_receipt(receipt_id, user)
                        if success:
                            self.stdout.write(
                                self.style.SUCCESS(f'Successfully retried receipt {log.receipt.invoice_number}')
                            )
                        else:
                            self.stdout.write(
                                self.style.ERROR(f'Failed to retry receipt {log.receipt.invoice_number}')
                            )
                    else:
                        self.stdout.write(
                            self.style.ERROR(f'No user found for receipt {log.receipt.invoice_number}')
                        )
                else:
                    self.stdout.write(
                        self.style.WARNING(f'Receipt {log.receipt.invoice_number} is not in failed state')
                    )
            except ReceiptSubmissionLog.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f'No submission log found for receipt ID {receipt_id}')
                )
        else:
            # Retry all failed submissions
            results = zimra_integration.retry_failed_submissions(max_retries)
            
            successful = len([r for r in results if r['success']])
            failed = len(results) - successful
            
            self.stdout.write(f'Retry completed:')
            self.stdout.write(f'  Successful: {successful}')
            self.stdout.write(f'  Failed: {failed}')
            
            if successful > 0:
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully retried {successful} receipts')
                )
            
            if failed > 0:
                self.stdout.write(
                    self.style.WARNING(f'{failed} receipts still failed after retry')
                )

        # Show current status summary
        pending_count = ReceiptSubmissionLog.objects.filter(submission_status='PENDING').count()
        submitted_count = ReceiptSubmissionLog.objects.filter(submission_status='SUBMITTED').count()
        failed_count = ReceiptSubmissionLog.objects.filter(submission_status='FAILED').count()
        retry_count = ReceiptSubmissionLog.objects.filter(submission_status='RETRY').count()

        self.stdout.write('\nCurrent Submission Status:')
        self.stdout.write(f'  Pending: {pending_count}')
        self.stdout.write(f'  Submitted: {submitted_count}')
        self.stdout.write(f'  Failed: {failed_count}')
        self.stdout.write(f'  Queued for Retry: {retry_count}')
