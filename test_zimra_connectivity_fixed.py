def test_zimra_connectivity(user, cert_path, key_path):
    """Test connectivity to ZIMRA API with proper authentication"""
    try:
        # ZIMRA FDMS API Configuration
        base_url = "https://fdmsapi.zimra.co.zw"  # Production URL
        # For testing, use: https://fdmsapitest.zimra.co.zw
        
        # Read certificate to get device ID if not set
        device_id = user.device_id or "TEST_DEVICE_001"
        
        # ZIMRA API requires specific headers
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "DeviceModelName": user.model_name or "FISCAL_DEVICE",
            "DeviceModelVersion": user.model_version or "1.0",
            "DeviceSerialNumber": user.zimra_serial_number or device_id,
            "ApplicationName": "PrimeConsultancy_FDMS",
            "ApplicationVersion": "1.0",
            "User-Agent": "PrimeConsultancy-FDMS/1.0"
        }
        
        # Check if certificates exist
        if not os.path.exists(cert_path):
            return {
                'connection_status': 'Certificate Missing',
                'last_test': timezone.now(),
                'error': f"Certificate not found at: {cert_path}",
                'response_time': None,
                'recommendations': [
                    "1. Generate or upload a valid certificate",
                    "2. Ensure certificate is in PEM format",
                    "3. Check file permissions"
                ]
            }
            
        if not os.path.exists(key_path):
            return {
                'connection_status': 'Private Key Missing',
                'last_test': timezone.now(),
                'error': f"Private key not found at: {key_path}",
                'response_time': None,
                'recommendations': [
                    "1. Generate or upload a valid private key",
                    "2. Ensure private key matches certificate",
                    "3. Check file permissions"
                ]
            }
        
        # ZIMRA FDMS API Endpoints (based on official documentation)
        endpoints_to_try = [
            {
                "url": f"{base_url}/ping",
                "method": "GET",
                "name": "Basic Connectivity Test"
            },
            {
                "url": f"{base_url}/api/health",
                "method": "GET",
                "name": "API Health Check"
            },
            {
                "url": f"{base_url}/Device/Status",
                "method": "GET",
                "name": "Device Status Check"
            },
            {
                "url": f"{base_url}/Device/GetConfiguration",
                "method": "GET", 
                "name": "Get Device Configuration"
            },
            {
                "url": f"{base_url}/Device/GetInfo",
                "method": "GET",
                "name": "Get Device Information"
            }
        ]
        
        successful_connections = []
        failed_connections = []
        
        for endpoint in endpoints_to_try:
            try:
                print(f"Testing ZIMRA endpoint: {endpoint['name']} - {endpoint['url']}")
                
                # Configure SSL session
                session = requests.Session()
                
                # Load certificate and key
                session.cert = (cert_path, key_path)
                
                # ZIMRA requires specific SSL configuration
                session.verify = False  # For test environment
                
                start_time = timezone.now()
                
                # Make the API call
                if endpoint['method'] == 'GET':
                    response = session.get(
                        endpoint['url'], 
                        headers=headers, 
                        timeout=30
                    )
                else:
                    response = session.post(
                        endpoint['url'], 
                        headers=headers, 
                        json={}, 
                        timeout=30
                    )
                
                response_time = (timezone.now() - start_time).total_seconds()
                
                print(f"Response Status: {response.status_code}")
                print(f"Response Headers: {dict(response.headers)}")
                print(f"Response Body: {response.text[:300]}...")
                
                if response.status_code in [200, 201, 202]:
                    # Success
                    try:
                        response_data = response.json()
                    except:
                        response_data = {"raw_response": response.text}
                    
                    successful_connections.append({
                        'endpoint': endpoint['name'],
                        'url': endpoint['url'],
                        'status_code': response.status_code,
                        'response_time': response_time,
                        'data': response_data
                    })
                    
                    # Return on first successful connection
                    return {
                        'connection_status': 'Connected',
                        'last_test': timezone.now(),
                        'successful_endpoint': endpoint['name'],
                        'response_time': response_time,
                        'zimra_response': response_data,
                        'all_results': {
                            'successful': successful_connections,
                            'failed': failed_connections
                        }
                    }
                elif response.status_code == 401:
                    # Authentication error - likely certificate or registration issue
                    failed_connections.append({
                        'endpoint': endpoint['name'],
                        'url': endpoint['url'],
                        'status_code': response.status_code,
                        'error': "Authentication failed - device may not be registered",
                        'response_time': response_time,
                        'response_text': response.text
                    })
                elif response.status_code == 403:
                    # Forbidden - certificate valid but access denied
                    failed_connections.append({
                        'endpoint': endpoint['name'],
                        'url': endpoint['url'],
                        'status_code': response.status_code,
                        'error': "Access forbidden - certificate valid but permissions denied",
                        'response_time': response_time,
                        'response_text': response.text
                    })
                else:
                    # Other HTTP errors
                    failed_connections.append({
                        'endpoint': endpoint['name'],
                        'url': endpoint['url'],
                        'status_code': response.status_code,
                        'error': f"HTTP {response.status_code}: {response.text}",
                        'response_time': response_time
                    })
                    
            except requests.exceptions.SSLError as ssl_error:
                print(f"SSL Error for {endpoint['name']}: {ssl_error}")
                failed_connections.append({
                    'endpoint': endpoint['name'],
                    'url': endpoint['url'],
                    'error': f"SSL Error: {ssl_error}",
                    'error_type': 'SSL'
                })
                
            except requests.exceptions.ConnectionError as conn_error:
                print(f"Connection Error for {endpoint['name']}: {conn_error}")
                failed_connections.append({
                    'endpoint': endpoint['name'],
                    'url': endpoint['url'],
                    'error': f"Connection Error: {conn_error}",
                    'error_type': 'Connection'
                })
                
            except requests.exceptions.Timeout as timeout_error:
                print(f"Timeout Error for {endpoint['name']}: {timeout_error}")
                failed_connections.append({
                    'endpoint': endpoint['name'],
                    'url': endpoint['url'],
                    'error': f"Timeout Error: {timeout_error}",
                    'error_type': 'Timeout'
                })
                
            except Exception as e:
                print(f"Error for {endpoint['name']}: {e}")
                failed_connections.append({
                    'endpoint': endpoint['name'],
                    'url': endpoint['url'],
                    'error': str(e),
                    'error_type': 'General'
                })
        
        # If we get here, all endpoints failed
        # Analyze failures to provide better recommendations
        ssl_errors = [f for f in failed_connections if f.get('error_type') == 'SSL']
        auth_errors = [f for f in failed_connections if '401' in str(f.get('status_code', ''))]
        connection_errors = [f for f in failed_connections if f.get('error_type') == 'Connection']
        
        recommendations = []
        if ssl_errors:
            recommendations.extend([
                "SSL Issues detected:",
                "- Check if certificate and private key match",
                "- Verify certificate is valid and not expired",
                "- Ensure certificate is issued by ZIMRA"
            ])
        if auth_errors:
            recommendations.extend([
                "Authentication Issues detected:",
                "- Register device with ZIMRA first",
                "- Verify device ID matches registration",
                "- Check if device is approved by ZIMRA"
            ])
        if connection_errors:
            recommendations.extend([
                "Connection Issues detected:",
                "- Check internet connectivity",
                "- Verify ZIMRA API URL is correct",
                "- Try switching between test and production URLs"
            ])
        
        return {
            'connection_status': 'All Endpoints Failed',
            'last_test': timezone.now(),
            'error': "All ZIMRA API endpoints returned errors",
            'all_results': {
                'successful': successful_connections,
                'failed': failed_connections
            },
            'recommendations': recommendations or [
                "1. Check if your device is registered with ZIMRA",
                "2. Verify certificate is valid and not expired", 
                "3. Confirm device ID matches ZIMRA registration",
                "4. Check if ZIMRA API base URL is correct",
                "5. Ensure all required headers are present"
            ]
        }
            
    except Exception as e:
        return {
            'connection_status': 'Configuration Error',
            'last_test': timezone.now(),
            'error': f"Configuration error: {str(e)}",
            'response_time': None,
            'recommendations': [
                "Check system configuration",
                "Verify file permissions",
                "Ensure all required dependencies are installed"
            ]
        }
