from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from utils.checker import check_host, check_bulk_hosts
from utils.emailer import send_alert
import os

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
        return render_template('bulk_results.html', results=results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# @app.route('/send_alert', methods=['POST'])
# def send_alert_route():
#     try:
#         recipients = request.form.get('recipients', '')
#         message = request.form.get('message', '')

#         if not recipients or not message:
#             return jsonify({'status': 'error', 'message': 'Recipients and message are required.'}), 400

#         recipient_list = recipients.split(',')
#         send_alert(recipient_list, message)

#         return jsonify({'status': 'success', 'message': 'Alerts sent successfully'})
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': str(e)}), 500
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

#         send_alert(recipient_list, message)

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

        return jsonify({'status': 'success', 'message': 'Alerts sent successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500




@app.route('/send_alert_page')
def send_alert_page():
    # Render the send_alert_page.html template
    hostname = request.args.get('hostname')
    recipients = request.args.get('recipients', '').split(',')  # Extract recipients from query parameters
    result = check_host(hostname) 
    return render_template('send_alert_page.html', hostname=hostname, recipients=recipients, result=result)

if __name__ == '__main__':
    app.run(debug=True)
