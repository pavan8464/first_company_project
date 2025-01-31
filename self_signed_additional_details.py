import ssl
import socket
import OpenSSL
from urllib.parse import urlparse

def get_cert_details(hostname):
    context = ssl.create_default_context()
    context.check_hostname = False  # Disable hostname checking
    context.verify_mode = ssl.CERT_NONE  # Disable certificate validation

    with socket.create_connection((hostname, 443)) as conn:
        with context.wrap_socket(conn, server_hostname=hostname) as sock:
            cert_bin = sock.getpeercert(True)
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
            cert_details = {
                "Subject": dict(cert.get_subject().get_components()),
                "Issuer": dict(cert.get_issuer().get_components()),
                "Not Before": cert.get_notBefore().decode('utf-8'),
                "Not After": cert.get_notAfter().decode('utf-8'),
                "Serial Number": cert.get_serial_number(),
                "Public Key": OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey()).decode()
            }
            return cert, cert_details

def is_self_signed(cert):
    # A self-signed certificate has the same issuer and subject
    return cert.get_issuer() == cert.get_subject()

def print_cert_details(hostname, details, self_signed):
    subject = details["Subject"]
    status = "self signed" if self_signed else "non-self signed"
    print(f"Host: {hostname} : {status}")
    print(f"Country: {subject.get(b'C', b'Field not available').decode('utf-8')}")
    print(f"State: {subject.get(b'ST', b'Field not available').decode('utf-8')}")
    print(f"City/Locality: {subject.get(b'L', b'Field not available').decode('utf-8')}")
    print(f"Organization: {subject.get(b'O', b'Field not available').decode('utf-8')}")
    print(f"Common Name (CN): {subject.get(b'CN', b'Field not available').decode('utf-8')}")
    print("\n")

def check_certificate(hostname):
    cert, details = get_cert_details(hostname)
    if cert is not None and details is not None:
        self_signed = is_self_signed(cert)
        print_cert_details(hostname, details, self_signed)
    else:
        print(f"Failed to retrieve certificate details for {hostname}\n")

def check_multiple_certificates(hostnames):
    for hostname in hostnames:
        check_certificate(hostname)

# List of hosts to check
hosts = ["self-signed.badssl.com", "google.com", "facebook.com", "expired.badssl.com"]

# Check certificates for multiple hosts
check_multiple_certificates(hosts)
