from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_file, session
from utils.checker import check_host, check_bulk_hosts
from utils.emailer import send_alert
from utils.port_scanner import scan_ports
import os
import csv
from io import StringIO, BytesIO
from reportlab.lib.pagesizes import landscape, A3
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib.units import inch  

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'
app.secret_key = 'your_secret_key_here'  # Add a secret key for flash messages

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Single host check route
# @app.route('/check', methods=['POST'])
# def check():
#     try:
#         hostname = request.form.get('hostname')
#         port = int(request.form.get('port', 0))
#         if not hostname or not port:
#             flash('Hostname and Port are required.', 'error')
#             return redirect(url_for('home'))

#         result = check_host(hostname, port)
#         return render_template('results.html', result=result)
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
# @app.route('/check', methods=['POST'])
# def check():
#     try:
#         hostname = request.form.get('hostname')
#         port = request.form.get('port')
#         unknown_port = 'unknown_port' in request.form
#         if not hostname:
#             flash('Hostname is required.', 'error')
#             return redirect(url_for('home'))

#         if unknown_port:
#             start_port = int(request.form.get('start_port'))
#             end_port = int(request.form.get('end_port'))
#             if start_port > end_port:
#                 flash('Start port cannot be greater than end port.', 'error')
#                 return redirect(url_for('home'))
#             results = scan_ports(hostname, start_port, end_port)
#             return render_template('results.html', result=results, open_ports=results['open_ports'])
#         else:
#             port = int(port)
#             result = check_host(hostname, port)
#             return render_template('results.html', result=result, open_ports=result.get('open_ports', []))
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
@app.route('/check', methods=['POST'])
def check():
    try:
        hostname = request.form.get('hostname')
        port = request.form.get('port')
        unknown_port = 'unknown_port' in request.form
        if not hostname:
            flash('Hostname is required.', 'error')
            return redirect(url_for('home'))

        if unknown_port:
            start_port = int(request.form.get('start_port'))
            end_port = int(request.form.get('end_port'))
            if start_port > end_port:
                flash('Start port cannot be greater than end port.', 'error')
                return redirect(url_for('home'))
            results = scan_ports(hostname, start_port, end_port)
            return render_template('results.html', result=results, open_ports=results['open_ports'])
        else:
            port = int(port)
            result = check_host(hostname, port)
            return render_template('results.html', result=result, open_ports=result.get('open_ports', []))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/scan', methods=['GET'])
def scan():
    hostname = request.args.get('hostname')
    start_port = int(request.args.get('startPort'))
    end_port = int(request.args.get('endPort'))

    results = scan_ports(hostname, start_port, end_port)
    return jsonify(results)


# Bulk check route
# @app.route('/bulk', methods=['POST'])
# def bulk_check():
#     try:
#         file = request.files.get('csv_file')
#         if not file:
#             flash('Please upload a CSV file.', 'error')
#             return redirect(url_for('home'))

#         filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
#         os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)  # Ensure the folder exists
#         file.save(filepath)

#         results = check_bulk_hosts(filepath)
#         session['results'] = results  # Save results in session for export
#         return render_template('bulk_results.html', results=results)
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
@app.route('/bulk', methods=['POST'])
def bulk_check():
    try:
        file = request.files.get('csv_file')
        if not file:
            flash('Please upload a CSV file.', 'error')
            return redirect(url_for('home'))

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)  # Ensure the folder exists
        file.save(filepath)

        results = check_bulk_hosts(filepath)
        session['results'] = results  # Save results in session for export

        # Use a redirect to avoid form resubmission
        return redirect(url_for('bulk_results'))
    except Exception as e:
        flash(str(e), 'error')
        return redirect(url_for('home'))

@app.route('/bulk_results')
def bulk_results():
    results = session.get('results', [])
    return render_template('bulk_results.html', results=results)

@app.route('/check_certificate', methods=['GET'])
def check_cert():
    hostname = request.args.get('hostname')
    if not hostname:
        return jsonify({"error": "Please provide a hostname"}), 400
    
    result = check_certificate(hostname)
    return jsonify(result)


# Send alert route
# @app.route('/send_alert', methods=['POST'])
# def send_alert_route():
#     try:
#         recipients = request.form.get('recipients', '')
#         hostname = request.form.get('hostname', '')

#         if not recipients:
#             return jsonify({'status': 'error', 'message': 'Recipients are required.'}), 400

#         recipient_list = recipients.split(',')

#         # Fetch the host status message
#         result = check_host(hostname)
#         message = f"Status of the host: {result['status']}"

#         send_alert(recipient_list, message, result)  # Pass the result object to send_alert

#         return jsonify({'status': 'success', 'message': 'Alerts sent successfully'})
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': str(e)}), 500
@app.route('/send_alert', methods=['POST'])
def send_alert_route():
    try:
        recipients = request.form.get('recipients', '')
        hostname = request.form.get('hostname', '')

        if not recipients:
            return jsonify({'status': 'error', 'message': 'Recipients are required.'}), 400

        recipient_list = recipients.split(',')

        # Fetch the host status message
        result = check_host(hostname)
        message = f"Status of the host: {result['status']}"

        send_alert(recipient_list, message, result)  # Pass the result object to send_alert

        # Instead of returning JSON, use redirect to avoid resubmission on browser back navigation
        flash('Alert sent successfully!', 'success')
        return redirect(url_for('send_alert_page', hostname=hostname, recipients=",".join(recipient_list)))
    except Exception as e:
        flash(str(e), 'error')
        return redirect(url_for('send_alert_page', hostname=hostname, recipients=",".join(recipient_list)))


# Send alert page route
@app.route('/send_alert_page')
def send_alert_page():
    hostname = request.args.get('hostname')
    recipients = request.args.get('recipients', '').split(',')

    # Retrieve the result details for the specified host
    result = check_host(hostname)  # Ensure this function returns the required details

    return render_template('send_alert_page.html', hostname=hostname, recipients=recipients, result=result)

# Export results to CSV route
@app.route('/export_csv', methods=['GET'])
def export_csv():
    results = session.get('results', [])
    si = StringIO()
    cw = csv.writer(si)
    
    # Write header
    cw.writerow(['Hostname', 'Port', 'Reachable', 'TLS Version', 'Certificate Expiry', 'Days Left', 'Certificate Issuer', 'Certificate Type', 'Status'])
    
    # Write data
    for result in results:
        cw.writerow([
            result['hostname'], result['port'], 'Yes' if result['reachable'] else 'No',
            ', '.join(result['tls_version']) if result['tls_version'] else 'N/A',
            result['certificate'].get('valid_to', 'N/A'), result['days_left'],
            result['certificate'].get('issuer', 'N/A'),
            # result['certificate'].get('type', 'N/A'),
            result['certificate_type'],
            result['status']
        ])
    
    output = BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='bulk_check_results.csv')

# Export results to PDF route
@app.route('/export_pdf', methods=['GET'])
def export_pdf():
    results = session.get('results', [])

    buffer = BytesIO()
    # Using A3 size for better width management
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A3))
    elements = []

    # Define the table headers
    headers = ['Hostname', 'Port', 'Reachable', 'TLS Version', 'Certificate Expiry', 'Days Left', 'Certificate Issuer', 'Certificate Type', 'Status']
    data = [headers]

    # Add the data to the table
    for result in results:
        row = [
            result['hostname'],
            str(result['port']),
            'Yes' if result['reachable'] else 'No',
            ', '.join(result['tls_version']) if result['tls_version'] else 'N/A',
            result['certificate'].get('valid_to', 'N/A'),
            str(result['days_left']) if result['days_left'] is not None else 'N/A',
            result['certificate'].get('issuer', 'N/A'),
            # result['certificate'].get('type', 'N/A'),
            result['certificate_type'],
            result['status']
        ]
        data.append(row)

    # Create the table
    table = Table(data, colWidths=[2*inch, 0.7*inch, 0.8*inch, 2.5*inch, 1.7*inch, 0.9*inch, 3*inch, 2*inch, 1.5*inch])

    # Add style to the table
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ])
    table.setStyle(style)

    elements.append(table)
    doc.build(elements)

    buffer.seek(0)

    return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name='bulk_check_results.pdf')

if __name__ == '__main__':
    app.run(debug=True)
