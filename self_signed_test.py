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

                return cert_details, is_self_signed(x509)

    except ssl.SSLCertVerificationError:
        # If there's an SSL verification error, try again with SSL verification disabled
        context = ssl._create_unverified_context()
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

                return cert_details, is_self_signed(x509)
        
    except Exception as e:
        return None, None

# Function to check if the certificate of a host is self-signed
def check_self_signed(hostname, port=443):
    if not check_network_connection(hostname, port):
        return f"{hostname} : Host Unreachable", False

    cert_details, self_signed = get_tls_and_certificate_details(hostname, port)
    if cert_details:
        status = "self signed" if self_signed else "non-self signed"
        return f"{hostname} : {status}", self_signed
    else:
        return f"{hostname} : No certificate details found", False

if __name__ == "__main__":
    hosts = ["google.com", "facebook.com", "expired.badssl.com", "self-signed.badssl.com", "amazon.in"]
    port = 443

    for host in hosts:
        status, _ = check_self_signed(host, port)
        print(status)
