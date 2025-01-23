import ssl
import socket

def get_tls_and_certificate_details(hostname, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                print("TLS Version:", tls_version)  # Debug print

                cert = ssock.getpeercert()
                print("Certificate:", cert)  # Debug print

                # Extract and format issuer details
                raw_issuer = cert.get('issuer', [])
                print("Raw Issuer:", raw_issuer)  # Debug print

                issuer_details = "\n".join(
                    f"- {name}: {value}" for item in raw_issuer for name, value in item
                )
                print("Issuer Details:", issuer_details)  # Debug print

                cert_details = {
                    'valid_from': cert.get('notBefore'),
                    'valid_to': cert.get('notAfter'),
                    'issuer': issuer_details,
                    'subject': cert.get('subject', []),
                }
                return tls_version, cert_details
    except Exception as e:
        print("Error:", e)  # Print the exception message
        return None, None

hostname = 'www.google.com'
port = 443
tls_version, cert_details = get_tls_and_certificate_details(hostname, port)
print("TLS Version:", tls_version)
print("Certificate Details:", cert_details)
