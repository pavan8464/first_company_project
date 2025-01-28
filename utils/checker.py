import os
import socket
import ssl
import csv
from datetime import datetime
import warnings

# Ensure the upload directory exists
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Function to check network connectivity for a given hostname and port
def check_network_connection(hostname, port):
    try:
        with socket.create_connection((hostname, port), timeout=5):
            return True
    except Exception:
        return False

def is_self_signed(cert):
    # Check if the issuer and subject are the same
    issuer = dict(x[0] for x in cert.get('issuer', ()))
    subject = dict(x[0] for x in cert.get('subject', ()))
    return issuer == subject


# Function to get TLS version and certificate details
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

                with socket.create_connection((hostname, port)) as conn:
                    with context.wrap_socket(conn, server_hostname=hostname) as sock:
                        cert = sock.getpeercert()
                        if not is_self_signed(cert):
                            supported_versions.append(version_name)
            except ssl.SSLError:
                pass

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                raw_issuer = cert.get('issuer', [])
                issuer_details = "\n".join(
                    f"- {name}: {value}" for item in raw_issuer for name, value in item
                )

                cert_details = {
                    'valid_from': cert.get('notBefore'),
                    'valid_to': cert.get('notAfter'),
                    'issuer': issuer_details,
                    'subject': cert.get('subject', []),
                }

        if not is_self_signed(cert):
            return supported_versions, cert_details

        # Handling self-signed certificates
        context.check_hostname = False  # Allow self-signed certificates
        context.verify_mode = ssl.CERT_NONE  # Allow self-signed certificates

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                raw_issuer = cert.get('issuer', [])
                issuer_details = "\n".join(
                    f"- {name}: {value}" for item in raw_issuer for name, value in item
                )

                cert_details = {
                    'valid_from': cert.get('notBefore'),
                    'valid_to': cert.get('notAfter'),
                    'issuer': issuer_details,
                    'subject': cert.get('subject', []),
                }

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
        'days_left': None
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

        # Log the fetched details for debugging purposes
        # print(f"TLS Version: {tls_version}, Cert Details: {cert_details}")

        result['tls_version'] = tls_version
        result['certificate'] = cert_details or {}

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
def save_uploaded_file(file, upload_dir=UPLOAD_FOLDER):
    try:
        file_path = os.path.join(upload_dir, file.filename)
        file.save(file_path)
        return file_path
    except Exception as e:
        print(f"Error saving uploaded file: {e}")
        return None


# Example usage for testing purposes
if __name__ == "__main__":
    # Example: Single host check
    hostname = "google.com"
    port = 443
    print(check_host(hostname, port))

    # Example: Bulk host processing
    sample_csv = "sample_hosts.csv"  # Ensure this file exists in the same directory
    results = check_bulk_hosts(sample_csv)
    for result in results:
        print(result)
