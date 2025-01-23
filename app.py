from flask import Flask, render_template, request, redirect, url_for, jsonify
from utils.checker import check_host, check_bulk_hosts
from utils.emailer import send_alert
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    hostname = request.form['hostname']
    port = int(request.form['port'])
    result = check_host(hostname, port)
    return render_template('results.html', result=result)

@app.route('/bulk', methods=['POST'])
def bulk_check():
    file = request.files['csv_file']
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    results = check_bulk_hosts(filepath)
    return render_template('bulk_results.html', results=results)

@app.route('/send_alert', methods=['POST'])
def send_alert_route():
    recipients = request.form['recipients']
    message = request.form['message']
    send_alert(recipients.split(','), message)
    return jsonify({'status': 'success', 'message': 'Alerts sent successfully'})

if __name__ == '__main__':
    app.run(debug=True)
