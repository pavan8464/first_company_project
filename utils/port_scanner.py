import socket
import time
from utils.checker import get_tls_and_certificate_details
# import sys

# def scan_ports(host, start_port, end_port):
#     open_ports = set()  # Use a set to avoid duplicates
#     total_ports = end_port - start_port + 1
#     measured_times = []
#     estimated_total_time = None

#     start_time = time.time()

#     for index, port in enumerate(range(start_port, min(start_port + 5, end_port + 1)), start=1):
#         port_start_time = time.time()
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             s.settimeout(0.5)
#             result = s.connect_ex((host, port))
#             if result == 0:
#                 open_ports.add(port)  # Add to set to avoid duplicates
#         time_taken = time.time() - port_start_time
#         measured_times.append(time_taken)

#     avg_time_per_port = sum(measured_times) / len(measured_times)
#     estimated_total_time = avg_time_per_port * total_ports

#     results = {
#         'estimated_total_time': estimated_total_time,
#         'progress': [],
#         'open_ports': list(open_ports),  # Convert set to list for JSON serialization
#         'hostname': host,
#         'port': f"{start_port}-{end_port}",
#         'reachable': True,
#         'tls_version': None,  # Adjust if needed
#         'certificate': {}  # Adjust if needed
#     }

#     for index, port in enumerate(range(start_port, end_port + 1), start=1):
#         port_start_time = time.time()
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             s.settimeout(0.5)
#             result = s.connect_ex((host, port))
#             if result == 0:
#                 open_ports.add(port)  # Add to set to avoid duplicates
#         elapsed_time = time.time() - start_time
#         estimated_time_remaining = max(estimated_total_time - elapsed_time, 0)
#         results['progress'].append({
#             'port': port,
#             'estimated_time_remaining': estimated_time_remaining
#         })

#     # Fetch certificate details for each open port
#     if open_ports:
#         # We'll fetch the certificate details from one of the open ports (e.g., the first one)
#         for open_port in open_ports:
#             _, cert_details = get_tls_and_certificate_details(host, open_port)
#             if cert_details:
#                 results['tls_version'] = cert_details.get('tls_version', [])
#                 results['certificate'] = cert_details
#                 break

#     results['open_ports'] = list(open_ports)  # Convert set to list for JSON serialization
# import warnings

# def scan_ports(host, start_port, end_port):
#     open_ports = set()  # Use a set to avoid duplicates
#     total_ports = end_port - start_port + 1
#     measured_times = []
#     estimated_total_time = None

#     start_time = time.time()

#     for index, port in enumerate(range(start_port, min(start_port + 5, end_port + 1)), start=1):
#         port_start_time = time.time()
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             s.settimeout(0.5)
#             result = s.connect_ex((host, port))
#             if result == 0:
#                 open_ports.add(port)  # Add to set to avoid duplicates
#         time_taken = time.time() - port_start_time
#         measured_times.append(time_taken)

#     avg_time_per_port = sum(measured_times) / len(measured_times)
#     estimated_total_time = avg_time_per_port * total_ports

#     results = {
#         'estimated_total_time': estimated_total_time,
#         'progress': [],
#         'open_ports': list(open_ports),  # Convert set to list for JSON serialization
#         'hostname': host,
#         'port': f"{start_port}-{end_port}",
#         'reachable': True,
#         'tls_version': [],
#         'certificate': {}
#     }

#     for index, port in enumerate(range(start_port, end_port + 1), start=1):
#         port_start_time = time.time()
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             s.settimeout(0.5)
#             result = s.connect_ex((host, port))
#             if result == 0:
#                 open_ports.add(port)  # Add to set to avoid duplicates
                
#                 # Get TLS and certificate details for each open port
#                 tls_version, cert_details = get_tls_and_certificate_details(host, port)
#                 if cert_details:
#                     results['tls_version'].extend(tls_version)
#                     results['certificate'] = cert_details
#                     break  # Exit the loop as we have found a valid certificate

#         elapsed_time = time.time() - start_time
#         estimated_time_remaining = max(estimated_total_time - elapsed_time, 0)
#         results['progress'].append({
#             'port': port,
#             'estimated_time_remaining': estimated_time_remaining
#         })

#     results['open_ports'] = list(open_ports)  # Convert set to list for JSON serialization
#     return results

# def scan_ports(host, start_port, end_port):
#     open_ports = set()  # Use a set to avoid duplicates
#     total_ports = end_port - start_port + 1
#     measured_times = []
#     estimated_total_time = None

#     start_time = time.time()

#     for index, port in enumerate(range(start_port, min(start_port + 5, end_port + 1)), start=1):
#         port_start_time = time.time()
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             s.settimeout(0.5)
#             result = s.connect_ex((host, port))
#             if result == 0:
#                 open_ports.add(port)  # Add to set to avoid duplicates
#         time_taken = time.time() - port_start_time
#         measured_times.append(time_taken)

#     avg_time_per_port = sum(measured_times) / len(measured_times)
#     estimated_total_time = avg_time_per_port * total_ports

#     results = {
#         'estimated_total_time': estimated_total_time,
#         'progress': [],
#         'open_ports': list(open_ports),  # Convert set to list for JSON serialization
#         'hostname': host,
#         'port': f"{start_port}-{end_port}",
#         'reachable': True,
#         'tls_version': [],
#         'certificate': {},
#         'checked_ports_range': f"{start_port}-{end_port}"  # Include the range of ports checked
#     }

#     for index, port in enumerate(range(start_port, end_port + 1), start=1):
#         port_start_time = time.time()
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             s.settimeout(0.5)
#             result = s.connect_ex((host, port))
#             if result == 0:
#                 open_ports.add(port)  # Add to set to avoid duplicates
                
#                 # Get TLS and certificate details for each open port
#                 tls_version, cert_details = get_tls_and_certificate_details(host, port)
#                 if cert_details:
#                     results['tls_version'].extend(tls_version)
#                     results['certificate'] = cert_details
#                     break  # Exit the loop as we have found a valid certificate

#         elapsed_time = time.time() - start_time
#         estimated_time_remaining = max(estimated_total_time - elapsed_time, 0)
#         results['progress'].append({
#             'port': port,
#             'estimated_time_remaining': estimated_time_remaining
#         })

#     results['open_ports'] = list(open_ports)  # Convert set to list for JSON serialization
#     return results

import socket
import time
import warnings

def scan_ports(host, start_port, end_port):
    open_ports = set()  # Use a set to avoid duplicates
    total_ports = end_port - start_port + 1
    measured_times = []
    estimated_total_time = None
    cert_port = None  # Initialize the port with certificate details

    start_time = time.time()

    for index, port in enumerate(range(start_port, min(start_port + 5, end_port + 1)), start=1):
        port_start_time = time.time()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((host, port))
            if result == 0:
                open_ports.add(port)  # Add to set to avoid duplicates
        time_taken = time.time() - port_start_time
        measured_times.append(time_taken)

    avg_time_per_port = sum(measured_times) / len(measured_times)
    estimated_total_time = avg_time_per_port * total_ports

    results = {
        'estimated_total_time': estimated_total_time,
        'progress': [],
        'open_ports': list(open_ports),  # Convert set to list for JSON serialization
        'hostname': host,
        'port': '',  # Placeholder for the port with certificate details
        'reachable': True,
        'tls_version': [],
        'certificate': {},
        'checked_ports_range': f"{start_port}-{end_port}"  # Include the range of ports checked
    }

    for index, port in enumerate(range(start_port, end_port + 1), start=1):
        port_start_time = time.time()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((host, port))
            if result == 0:
                open_ports.add(port)  # Add to set to avoid duplicates
                
                # Get TLS and certificate details for each open port
                tls_version, cert_details = get_tls_and_certificate_details(host, port)
                if tls_version and cert_details:  # Check if not None
                    results['tls_version'].extend(tls_version)
                    results['certificate'] = cert_details
                    results['port'] = port  # Set the port with certificate details
                    cert_port = port  # Set the cert_port to the current port
                    break  # Exit the loop as we have found a valid certificate

        elapsed_time = time.time() - start_time
        estimated_time_remaining = max(estimated_total_time - elapsed_time, 0)
        results['progress'].append({
            'port': port,
            'estimated_time_remaining': estimated_time_remaining
        })

    results['open_ports'] = list(open_ports)  # Convert set to list for JSON serialization
    if cert_port:
        results['port'] = cert_port  # Use cert_port if it's set
    else:
        results['port'] = 'None'  # Set 'None' if no certificate port found

    return results



# Example usage
if __name__ == "__main__":
    target_host = "google.com"  # Change to a remote IP or domain if needed
    start_port = 440
    end_port = 445  

    open_ports = scan_ports(target_host, start_port, end_port)
    if open_ports:
        print(f"Open ports on {target_host}: {open_ports}")
    else:
        print(f"No open ports found in the range {start_port}-{end_port}.")
