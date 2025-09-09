import os
import smtplib
from email.mime.text import MIMEText
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import traceback

load_dotenv()

app = Flask(__name__)

GMAIL_EMAIL = os.getenv("GMAIL_EMAIL")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

def send_email(to_email, subject, body):
    # msg = MIMEText(body)
    msg = MIMEText(body, 'html')
    msg['Subject'] = subject
    msg['From'] = GMAIL_EMAIL
    msg['To'] = to_email

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(GMAIL_EMAIL, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_EMAIL, to_email, msg.as_string())
        print(f"Email sent to {to_email}")
        return True, "Email sent successfully."
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")
        return False, str(e)

@app.route('/api/send_email', methods=['POST'])
def api_send_email():
    try:
        data = request.get_json()
        to_email = data['to_email']
        subject = data['subject']
        body = data['body']

        success, message = send_email(to_email, subject, body)

        if success:
            return jsonify({"status": "success", "message": message}), 200
        else:
            return jsonify({"status": "error", "message": message}), 500
    except Exception as e:
        traceback.print_exc()
        print(e)
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/')
def index():
    return "Mailer service is running."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
