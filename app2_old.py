from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_file, session
from utils.checker import check_host, check_bulk_hosts
from utils.emailer import send_alert
import os
import csv
from io import StringIO, BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'
app.secret_key = 'your_secret_key_here'  # Add a secret key for flash messages

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    try:
        hostname = request.form.get('hostname')
        port = int(request.form.get('port', 0))
        if not hostname or not port:
            flash('Hostname and Port are required.', 'error')
            return redirect(url_for('home'))

        result = check_host(hostname, port)
        return render_template('results.html', result=result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
        return render_template('bulk_results.html', results=results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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

        return jsonify({'status': 'success', 'message': 'Alerts sent successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/send_alert_page')
def send_alert_page():
    hostname = request.args.get('hostname')
    recipients = request.args.get('recipients', '').split(',')

    # Retrieve the result details for the specified host
    result = check_host(hostname)  # Ensure this function returns the required details

    return render_template('send_alert_page.html', hostname=hostname, recipients=recipients, result=result)

# Route to export results to CSV
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
            result['certificate'].get('type', 'N/A'),
            result['status']
        ])
    
    output = BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='bulk_check_results.csv')

# Route to export results to PDF
# @app.route('/export_pdf', methods=['GET'])
# def export_pdf():
#     results = session.get('results', [])
#     output = BytesIO()
#     p = canvas.Canvas(output, pagesize=letter)
#     width, height = letter

#     # Define a title and header
#     title = "Bulk Check Results"
#     p.drawString(250, height - 40, title)

#     # Define the table headers
#     headers = ['Hostname', 'Port', 'Reachable', 'TLS Version', 'Certificate Expiry', 'Days Left', 'Certificate Issuer', 'Certificate Type', 'Status']
#     for idx, header in enumerate(headers):
#         p.drawString(30 + idx * 80, height - 80, header)

#     # Define table rows
#     y = height - 100
#     for result in results:
#         p.drawString(30, y, result['hostname'])
#         p.drawString(110, y, str(result['port']))
#         p.drawString(190, y, 'Yes' if result['reachable'] else 'No')
#         p.drawString(270, y, ', '.join(result['tls_version']) if result['tls_version'] else 'N/A')
#         p.drawString(350, y, result['certificate'].get('valid_to', 'N/A'))
#         p.drawString(430, y, str(result['days_left']))
#         p.drawString(510, y, result['certificate'].get('issuer', 'N/A'))
#         p.drawString(590, y, result['certificate'].get('type', 'N/A'))
#         p.drawString(670, y, result['status'])
#         y -= 20
    
#     p.showPage()
#     p.save()
#     output.seek(0)
    
#     return send_file(output, mimetype='applicati=on/pdf', as_attachment=True, download_name='bulk_check_results.pdf')
@app.route('/export_pdf', methods=['GET'])
def export_pdf():
    results = session.get('results', [])
    output = BytesIO()
    p = canvas.Canvas(output, pagesize=letter)
    width, height = letter

    # Define a title and header
    title = "Bulk Check Results"
    p.drawString(250, height - 40, title)

    # Define the table headers
    headers = ['Hostname', 'Port', 'Reachable', 'TLS Version', 'Certificate Expiry', 'Days Left', 'Certificate Issuer', 'Certificate Type', 'Status']
    data = [headers]

    # Prepare the data rows
    for result in results:
        row = [
            result['hostname'],
            str(result['port']),
            'Yes' if result['reachable'] else 'No',
            ', '.join(result['tls_version']) if result['tls_version'] else 'N/A',
            result['certificate'].get('valid_to', 'N/A'),
            str(result['days_left']) if result['days_left'] is not None else 'N/A',
            result['certificate'].get('issuer', 'N/A'),
            result['certificate'].get('type', 'N/A'),
            result['status']
        ]
        data.append(row)

    # Create the table
    from reportlab.platypus import Table, TableStyle
    from reportlab.lib import colors

    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))

    # Position the table
    table.wrapOn(p, width, height)
    table.drawOn(p, 30, height - 100 - len(data) * 20)

    p.showPage()
    p.save()
    output.seek(0)

    return send_file(output, mimetype='application/pdf', as_attachment=True, download_name='bulk_check_results.pdf')


if __name__ == '__main__':
    app.run(debug=True)
