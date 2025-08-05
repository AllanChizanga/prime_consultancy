# Prime Consultancy - Fiscal Device Management System
**Version 2.1** | **Last Updated: August 2025**

---

## System Overview

Prime Consultancy's Fiscal Device Management System (FDMS) is a comprehensive web-based application designed to manage fiscal receipts and ensure compliance with Zimbabwe Revenue Authority (ZIMRA) regulations. The system provides automated receipt generation, tax calculations, and direct integration with ZIMRA's fiscal device management infrastructure.

## Core Functionality

### Receipt Management
The system generates sequential fiscal receipts with unique invoice numbers following the format `INV-00001`. Each receipt includes:
- Automatic counter assignment per fiscal day
- Global receipt numbering across all transactions
- Cryptographic hash generation for data integrity
- Tax calculations with support for multiple tax codes
- Buyer information management with TIN validation

### ZIMRA Integration
Direct API integration with ZIMRA's test environment (`fdmsapitest.zimra.co.zw`) enables:
- Real-time receipt submission to tax authorities
- Device registration and certificate management
- Fiscal day opening and closing operations
- Compliance status monitoring and reporting

### User Management
Multi-tier user system supporting:
- Client registration with company and device information
- Administrative user controls and permissions
- Device-specific certificate assignment
- Account activation workflows

## Technical Architecture

### Backend Framework
- **Django 4.x** with PostgreSQL/SQLite database
- **Django REST Framework** for API endpoints
- **JWT Authentication** for secure API access
- **Custom user model** with email-based authentication

### Database Schema
Key models include:
- `User`: Extended user model with company and device fields
- `Receipt`: Main transaction record with ZIMRA compliance fields
- `ReceiptLine`: Individual line items with tax calculations
- `ReceiptTax`: Tax breakdown per receipt
- `ReceiptSubmissionLog`: ZIMRA submission tracking
- `FiscalDay`: Daily fiscal period management

### API Endpoints
- `/api/receipts/` - Receipt CRUD operations
- `/api/users/` - User management
- `/api/fiscal-days/` - Fiscal day operations
- `/api/token/` - JWT authentication

## ZIMRA Compliance Features

### Certificate Management
Each registered device requires:
- Device-specific X.509 certificates stored in `/certificates/`
- Private key management for API authentication
- Certificate signing request (CSR) generation
- Automatic certificate renewal monitoring

### Receipt Validation
All receipts undergo validation including:
- Sequential numbering verification
- Tax calculation accuracy checks
- Hash generation using SHA-256 algorithm
- ZIMRA submission status tracking

### Audit Trail
Complete audit functionality provides:
- Submission timestamps and status codes
- Error message logging and retry attempts
- ZIMRA response data storage
- Compliance reporting capabilities

## Installation and Configuration

### System Requirements
- Python 3.8 or higher
- Django 4.0+
- PostgreSQL 12+ (recommended) or SQLite for development
- SSL certificates for ZIMRA API communication

### Environment Setup
1. Install dependencies: `pip install -r requirements.txt`
2. Configure database settings in `settings.py`
3. Run migrations: `python manage.py migrate`
4. Create superuser: `python manage.py createsuperuser`
5. Install device certificates in `/certificates/` directory

### ZIMRA Configuration
Configure the following in Django settings:
- ZIMRA API base URL (test/production)
- Certificate file paths
- Device model information
- Timeout and retry parameters

## User Interface

### Client Portal
- Invoice submission form with line item management
- Receipt history and status tracking
- Profile management and password changes
- Fiscal day operations

### Administrative Dashboard
- Client registration and activation
- Device management and configuration
- ZIMRA submission monitoring
- Compliance reporting and analytics

### ZIMRA Compliance Dashboard
- Real-time submission statistics
- Failed submission retry management
- Certificate status monitoring
- Audit log review

## Security Considerations

### Authentication
- Email-based user authentication
- JWT token-based API access
- Role-based permission system
- Session management and timeout controls

### Data Protection
- Receipt data encryption in transit
- Secure certificate storage
- Database connection encryption
- Audit logging for all operations

### ZIMRA Communication
- Client certificate authentication
- TLS 1.2+ for all API communications
- Request/response logging
- Automatic retry with exponential backoff

## Maintenance Procedures

### Daily Operations
- Monitor ZIMRA submission success rates
- Review failed submissions and retry queues
- Check certificate expiration dates
- Verify fiscal day operations

### Monthly Tasks
- Generate compliance reports
- Review audit logs for anomalies
- Update certificate inventory
- Performance monitoring and optimization

### Troubleshooting
Common issues and resolutions:
- Certificate authentication failures: Verify certificate validity and permissions
- Network timeout errors: Check ZIMRA API status and network connectivity
- Receipt validation errors: Review tax calculations and required fields
- Database connection issues: Verify database server status and credentials

## API Reference

### Authentication
All API requests require JWT token in Authorization header:
```
Authorization: Bearer <jwt_token>
```

### Receipt Submission
```http
POST /api/receipts/submit_receipt/
Content-Type: application/json

{
  "receipt_type": "FiscalInvoice",
  "currency": "USD",
  "buyer": {...},
  "receipt_lines": [...],
  "receipt_taxes": [...]
}
```

### Device Registration
```http
POST /api/csr/{id}/register_device/
Content-Type: application/json

{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----..."
}
```

## Error Codes and Messages

### ZIMRA API Responses
- `200`: Successful submission
- `400`: Invalid request data
- `401`: Authentication failure
- `500`: ZIMRA server error
- `503`: Service unavailable

### System Error Codes
- `CERT_NOT_FOUND`: Device certificate missing
- `DEVICE_NOT_CONFIGURED`: Incomplete device setup
- `TIMEOUT`: Request timeout exceeded
- `CONNECTION_ERROR`: Network connectivity issue

## Support and Contact

For technical support or system issues:
- Review system logs in Django admin
- Check ZIMRA submission dashboard
- Verify certificate and network configuration
- Contact system administrator for assistance

---

*This documentation covers the core functionality of the Prime Consultancy FDMS. For detailed API specifications or advanced configuration options, refer to the Django admin interface or contact the development team.*
