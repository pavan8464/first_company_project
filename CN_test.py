import os
import socket
import ssl
import warnings
from OpenSSL import crypto  # Ensure you have this module installed

# Function to check network connectivity for a given hostname and port
def check_network_connection(hostname, port):
    try:
        with socket.create_connection((hostname, port), timeout=5):
            return True
    except Exception:
        return False

# Function to check if a certificate is self-signed
def is_self_signed(cert):
    if isinstance(cert, dict):
        issuer = dict(x[0] for x in cert.get('issuer', ()))
        subject = dict(x[0] for x in cert.get('subject', ()))
        return issuer == subject
    elif isinstance(cert, crypto.X509):
        issuer = cert.get_issuer()
        subject = cert.get_subject()
        return issuer.get_components() == subject.get_components()
    else:
        return False

# Function to get TLS version and certificate details
def get_tls_and_certificate_details(hostname, port=443):
    try:
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bytes = ssock.getpeercert(binary_form=True)
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bytes)

                raw_issuer = x509.get_issuer()
                issuer_details = "\n".join(
                    f"- {name.decode('utf-8')}: {value.decode('utf-8')}"
                    for name, value in raw_issuer.get_components()
                )

                # Extract subject components
                subject_components = x509.get_subject().get_components()
                common_name = None
                for name, value in subject_components:
                    if name.decode('utf-8') == 'CN':
                        common_name = value.decode('utf-8')
                        break

                cert_details = {
                    'valid_from': x509.get_notBefore().decode('utf-8'),
                    'valid_to': x509.get_notAfter().decode('utf-8'),
                    'issuer': issuer_details,
                    'subject': [
                        (name.decode('utf-8'), value.decode('utf-8'))
                        for name, value in subject_components
                    ],
                    'common_name': common_name if common_name else "NA"
                }

                return cert_details

    except Exception as e:
        print(f"Error getting certificate details for {hostname}: {e}")
        return None

# Function to get Common Name (CN) of a host
def get_common_name(hostname, port=443):
    if not check_network_connection(hostname, port):
        print(f"Host {hostname} on port {port} is not reachable.")
        return None

    cert_details = get_tls_and_certificate_details(hostname, port)
    if cert_details and cert_details.get('common_name'):
        return cert_details['common_name']
    else:
        print(f"No certificate details found for {hostname}.")
        return None

if __name__ == "__main__":
    hosts = ["google.com", "facebook.com", "aig.service-now.com", "amazon.in"]
    port = 443

    for host in hosts:
        cn = get_common_name(host, port)
        print(f"Common Name for {host}: {cn}")
