import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_alert(recipients, message):
    sender_email = "your_email@example.com"
    sender_password = "your_password"

    for recipient in recipients:
        try:
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = recipient
            msg['Subject'] = "Certificate Alert"

            msg.attach(MIMEText(message, 'plain'))
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(msg)
        except Exception as e:
            print(f"Failed to send email to {recipient}: {e}")
