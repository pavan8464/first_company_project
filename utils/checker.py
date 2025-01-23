import os
import socket
import ssl
import csv
from datetime import datetime

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


# Function to get TLS version and certificate details
def get_tls_and_certificate_details(hostname, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                cert = ssock.getpeercert()

                # Extract and format issuer details
                raw_issuer = cert.get('issuer', [])
                issuer_details = "\n".join(
                    f"- {name}: {value}" for item in raw_issuer for name, value in item
                )
                # print(issuer_details)

                cert_details = {
                    'valid_from': cert.get('notBefore'),
                    'valid_to': cert.get('notAfter'),
                    'issuer': issuer_details,
                    'subject': cert.get('subject', []),
                }
                return tls_version, cert_details
    except Exception as e:
        return None, None



# Function to determine the status of a certificate based on its validity date
def determine_cert_status(cert_valid_to):
    if not cert_valid_to:
        return "Invalid"
    try:
        expiry_date = datetime.strptime(cert_valid_to, '%b %d %H:%M:%S %Y %Z')
        days_left = (expiry_date - datetime.now()).days
        if days_left < 0:
            return "Expired"
        elif days_left <= 30:
            return "Expiring Soon"
        return "Valid"
    except Exception as e:
        print(f"Error determining certificate status: {e}")
        return "Invalid"


# Function to check a single host and return its details
def check_host(hostname, port=443):
    reachable = check_network_connection(hostname, port)
    tls_version, cert_details = get_tls_and_certificate_details(hostname, port)

    result = {
        'hostname': hostname,
        'port': port,
        'reachable': reachable,
        'tls_version': tls_version,
        'certificate': cert_details or {},
        'status': None,
    }

    if cert_details:
        result['status'] = determine_cert_status(cert_details.get('valid_to'))
    else:
        result['status'] = "No Certificate"

    return result


# Function to process multiple hosts from a CSV file
def process_bulk_hosts(file_path):
    results = []
    try:
        with open(file_path, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                hostname = row.get('hostname')
                port = int(row.get('port', 443))  # Default to port 443 if not specified
                result = check_host(hostname, port)
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
