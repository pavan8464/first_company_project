import ssl
import socket
import warnings
import csv
from datetime import datetime
import os

# Function to check network connection
def check_network_connection(hostname, port):
    try:
        socket.create_connection((hostname, port), timeout=5)
        return True
    except (socket.timeout, socket.error):
        return False


def is_self_signed(cert):
    """Check if a certificate is self-signed."""
    try:
        subject = cert.get('subject', [])
        issuer = cert.get('issuer', [])
        return subject == issuer
    except Exception:
        return False


def get_tls_and_certificate_details(hostname, port=443):
    try:
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        
        versions = {
            'TLSv1': ssl.TLSVersion.TLSv1,
            'TLSv1.1': ssl.TLSVersion.TLSv1_1,
            'TLSv1.2': ssl.TLSVersion.TLSv1_2,
            'TLSv1.3': ssl.TLSVersion.TLSv1_3
        }
        
        supported_versions = []
        for version_name, version in versions.items():
            try:
                context = ssl.create_default_context()
                context.minimum_version = version
                context.maximum_version = version
                
                with socket.create_connection((hostname, port), timeout=5) as conn:
                    with context.wrap_socket(conn, server_hostname=hostname) as sock:
                        cert = sock.getpeercert()
                        if cert and not is_self_signed(cert):
                            supported_versions.append(version_name)
            except (ssl.SSLError, socket.timeout):
                pass

        def extract_cert_details(cert):
            """Extract relevant certificate details."""
            issuer_details = "\n".join(
                f"- {name}: {value}" for item in cert.get('issuer', []) for name, value in item
            )
            common_name = next((value for field in cert.get("subject", []) for key, value in field if key == "commonName"), "Unknown")
            return {
                'valid_from': cert.get('notBefore', 'Unknown'),
                'valid_to': cert.get('notAfter', 'Unknown'),
                'issuer': issuer_details,
                'subject': cert.get('subject', []),
                'common_name': common_name
            }
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_details = extract_cert_details(cert)
                
        if not is_self_signed(cert):
            return supported_versions, cert_details

        # Handle self-signed certificates
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_details = extract_cert_details(cert)
                
        return supported_versions, cert_details
    
    except Exception as e:
        return None, None


# Function to determine the status of a certificate based on its validity date
def determine_cert_status(cert_valid_to):
    if not cert_valid_to:
        return "Invalid", None
    try:
        # Convert the string 'valid_to' into a datetime object
        expiry_date = datetime.strptime(cert_valid_to, '%b %d %H:%M:%S %Y %Z')
        
        # Calculate the number of days left until expiration
        days_left = (expiry_date - datetime.now()).days
        if days_left < 0:
            return "Expired", days_left
        elif days_left <= 30:
            return f"Expiring Soon ({days_left} days left)", days_left
        return f"Valid ({days_left} days left)", days_left
    except Exception as e:
        print(f"Error determining certificate status: {e}")
        return "Invalid", None



# Function to check a single host and return its details
def check_host(hostname, port=443):
    # Initialize the result dictionary with default values
    result = {
        'hostname': hostname,
        'port': port,
        'reachable': False,
        'tls_version': None,
        'certificate': {},
        'status': "No Certificate",  # Default status for unreachable or no certificate
        'days_left': None,
        'common_name': None  # <-- Added field for CN
    }

    try:
        # Check network connectivity
        reachable = check_network_connection(hostname, port)
        result['reachable'] = reachable

        if not reachable:
            print(f"Host {hostname} on port {port} is not reachable.")
            result['status'] = "Host Unreachable"
            return result

        # Get TLS and certificate details
        tls_version, cert_details = get_tls_and_certificate_details(hostname, port)

        result['tls_version'] = tls_version
        result['certificate'] = cert_details or {}

        # Capture Common Name (CN)
        if cert_details:
            result['common_name'] = cert_details.get("common_name")  # <-- Extract CN

        # If no certificate details are found, set status to "No Certificate"
        if not cert_details:
            print(f"No certificate details for {hostname}.")
            result['status'] = "No Certificate"
        else:
            # Determine certificate validity and days left
            if cert_details.get('valid_to'):
                status, days_left = determine_cert_status(cert_details.get('valid_to'))
                result['status'] = status
                result['days_left'] = days_left
            else:
                print(f"Certificate 'valid_to' missing for {hostname}.")
                result['status'] = "No Certificate"
                result['days_left'] = None

    except Exception as e:
        print(f"Error checking host {hostname} on port {port}: {e}")
        result['status'] = "Error"
        result['days_left'] = None
    return result


def process_bulk_hosts(file_path):
    results = []
    try:
        with open(file_path, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                if row is None or not row:
                    print("Found empty or None row, skipping...")
                    continue
                
                print(f"Processing row: {row}")
                
                if 'hostname' not in row or 'port' not in row or 'recipients' not in row:
                    print(f"Skipping row with missing required fields: {row}")
                    continue
                
                hostname = row.get('hostname')
                if not hostname:
                    print(f"Skipping row with missing 'hostname': {row}")
                    continue
                
                try:
                    port = int(row.get('port', 443))  # Default to port 443 if not specified
                except ValueError:
                    print(f"Error: Invalid port value '{row.get('port')}', defaulting to 443 for hostname {hostname}")
                    port = 443  # Default to 443 in case of invalid port
                
                result = check_host(hostname, port)
                if result is None:
                    print(f"Warning: check_host returned None for {hostname} on port {port}")
                    continue

                # Add recipients to the result
                result['recipients'] = row.get('recipients')
                
                results.append(result)
    except FileNotFoundError:
        print(f"Error: File not found at path {file_path}")
    except Exception as e:
        print(f"Error processing bulk hosts: {e}")
    return results


# Function to check multiple hosts (wrapper for process_bulk_hosts)
def check_bulk_hosts(file_path):
    """
    Wrapper for process_bulk_hosts. This function adds additional functionality 
    or customization for bulk host checks if needed.
    """
    return process_bulk_hosts(file_path)


# Function to save uploaded file to the uploads directory
def save_uploaded_file(file, upload_dir='uploads'):
    try:
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        file_path = os.path.join(upload_dir, file.filename)
        file.save(file_path)
        return file_path
    except Exception as e:
        print(f"Error saving uploaded file: {e}")
        return None


# Example usage for testing purposes
if __name__ == "__main__":
    # Example: Single host check
    hostname = "self-signed.badssl.com"
    port = 443
    print(check_host(hostname, port))

    # Example: Bulk host check from CSV
    # file_path = "hosts.csv"  # Your CSV file path
    # results = check_bulk_hosts(file_path)
    # for result in results:
    #     print(result)
