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
                "Not Before": cert.get_notBefore().decode(),
                "Not After": cert.get_notAfter().decode(),
                "Serial Number": cert.get_serial_number(),
                "Public Key": OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey()).decode()
            }
            return cert, cert_details

def is_self_signed(cert):
    # A self-signed certificate has the same issuer and subject
    return cert.get_issuer() == cert.get_subject()

def check_certificate(hostname):
    cert, details = get_cert_details(hostname)
    if is_self_signed(cert):
        print(f"Certificate for {hostname} is Self-Signed")
    else:
        print(f"Certificate for {hostname} is NOT Self-Signed")
    print(f"Certificate Details for {hostname}:")
    for key, value in details.items():
        print(f"{key}: {value}")
    print("\n")

# Check certificates for self-signed.badssl.com and google.com
check_certificate("self-signed.badssl.com")
check_certificate("google.com")
