from flask import Flask, request, jsonify
from flask_cors import CORS
import openai
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from bs4 import BeautifulSoup
import logging
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

app = Flask(__name__)
CORS(app)  # Allow all origins for development

openai_client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
logging.basicConfig(level=logging.INFO)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.compose"
]

def get_gmail_service():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    service = build("gmail", "v1", credentials=creds)
    return service

def get_gmail_service_from_token(access_token):
    creds = Credentials(
        token=access_token,
        refresh_token=None,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=None,
        client_secret=None,
        scopes=[
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/gmail.compose"
        ]
    )
    service = build("gmail", "v1", credentials=creds)
    return service

@app.route('/chat', methods=['POST'])
def chat():
    data = request.json
    user_message = data.get('message', '')
    if not user_message:
        return jsonify({'error': 'No message provided'}), 400
    try:
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are Precort, a helpful assistant."},
                {"role": "user", "content": user_message}
            ]
        )
        reply = response.choices[0].message.content.strip()
        return jsonify({'reply': reply})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/voice-command', methods=['POST'])
def voice_command():
    data = request.get_json()
    command = data.get('command', '')
    logging.info(f"Received voice command: {command}")
    if not command:
        return jsonify({'reply': "No command received."}), 400
    try:
        # Web search using DuckDuckGo HTML scraping
        search_url = f'https://html.duckduckgo.com/html/?q={requests.utils.quote(command)}'
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(search_url, headers=headers, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        results = []
        for result in soup.select('.result__snippet')[:3]:
            results.append(result.get_text(strip=True))
        if not results:
            reply = 'No relevant web results found.'
        else:
            reply = '\n'.join(results)
    except Exception as e:
        logging.error(f"Error in /voice-command: {e}")
        reply = f"Error searching the web: {e}"
    return jsonify({'reply': reply})

@app.route('/send-contact-email', methods=['POST'])
def send_contact_email():
    data = request.get_json()
    name = data.get('name', '').strip()
    message = data.get('message', '').strip()
    if not name or not message:
        return jsonify({'error': 'Name and message are required.'}), 400
    # Prepare email
    recipient = 'shauryakhurana2013@gmail.com'
    subject = f'Precort Contact Form Message from {name}'
    body = f'Name: {name}\nMessage: {message}'
    # SMTP config from environment
    smtp_host = os.getenv('SMTP_HOST')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    smtp_user = os.getenv('SMTP_USER')
    smtp_pass = os.getenv('SMTP_PASS')
    sender = smtp_user
    try:
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(sender, recipient, msg.as_string())
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': f'Failed to send email: {e}'}), 500

@app.route('/apricot-email-assistant', methods=['POST'])
def apricot_email_assistant():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'reply': 'Missing or invalid Authorization header'}), 401
    access_token = auth_header.split(' ')[1]
    service = get_gmail_service_from_token(access_token)
    data = request.get_json()
    command = data.get('command', '')
    if not command:
        return jsonify({'reply': "No command received."}), 400
    # Use OpenAI to extract intent
    system_prompt = (
        "You are an AI that processes email voice commands. "
        "Given a user sentence, summarize the intent clearly like: "
        "'summarize unread emails', 'reply to John', 'delete latest email', "
        "'archive latest email', 'forward last email to Alice', etc. "
        "If the user wants to reply, forward, draft, or send, include the action and recipient if possible."
    )
    try:
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": command}
            ]
        )
        intent = response.choices[0].message.content.strip().lower()
    except Exception as e:
        return jsonify({'reply': f'OpenAI error: {e}'}), 500
    # For now, just echo the intent. Next, add logic for summarize, reply, etc.
    # Summarize unread emails
    if "summarize unread" in intent:
        try:
            results = service.users().messages().list(
                userId='me',
                labelIds=['UNREAD', 'CATEGORY_PERSONAL', 'INBOX'],
                maxResults=5,
                q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
            ).execute()
            messages = results.get('messages', [])
            if not messages:
                return jsonify({'reply': "You have no unread emails in your Primary inbox."})
            summaries = []
            for msg in messages:
                msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
                headers = msg_data['payload'].get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
                summaries.append(f"Email from {sender}: {subject}")
            return jsonify({'reply': '\n'.join(summaries)})
        except HttpError as e:
            return jsonify({'reply': f"Failed to fetch emails: {e}"})
    # Archive latest email
    if "archive" in intent:
        try:
            results = service.users().messages().list(
                userId='me',
                maxResults=1,
                labelIds=['UNREAD', 'CATEGORY_PERSONAL', 'INBOX'],
                q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
            ).execute()
            messages = results.get('messages', [])
            if not messages:
                return jsonify({'reply': "No email found to archive."})
            msg_id = messages[0]['id']
            service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['INBOX']}).execute()
            return jsonify({'reply': "Email archived."})
        except HttpError as e:
            return jsonify({'reply': f"Failed to archive: {e}"})
    # Delete latest email
    if "delete" in intent or "trash" in intent:
        try:
            results = service.users().messages().list(
                userId='me',
                maxResults=1,
                labelIds=['UNREAD', 'CATEGORY_PERSONAL', 'INBOX'],
                q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
            ).execute()
            messages = results.get('messages', [])
            if not messages:
                return jsonify({'reply': "No email found to delete."})
            msg_id = messages[0]['id']
            service.users().messages().trash(userId='me', id=msg_id).execute()
            return jsonify({'reply': "Email moved to Trash."})
        except HttpError as e:
            return jsonify({'reply': f"Failed to delete: {e}"})
    # Reply to latest email
    if "reply" in intent:
        try:
            # Get latest email
            results = service.users().messages().list(
                userId='me',
                maxResults=1,
                labelIds=['UNREAD', 'CATEGORY_PERSONAL', 'INBOX'],
                q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
            ).execute()
            messages = results.get('messages', [])
            if not messages:
                return jsonify({'reply': "No email found to reply to."})
            msg_id = messages[0]['id']
            msg_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
            headers = msg_data['payload'].get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
            snippet = msg_data.get('snippet', '')
            # Use OpenAI to generate a reply body
            reply_prompt = f"Write a short, polite reply to this email:\nFrom: {sender}\nSubject: {subject}\nSnippet: {snippet}"
            reply_response = openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": reply_prompt}]
            )
            reply_body = reply_response.choices[0].message.content.strip()
            # Send the reply
            from email.mime.text import MIMEText
            import base64
            message = MIMEText(reply_body)
            message['to'] = sender
            message['subject'] = "Re: " + subject
            raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
            msg = {'raw': raw, 'threadId': msg_id}
            service.users().messages().send(userId='me', body=msg).execute()
            return jsonify({'reply': "Reply sent."})
        except Exception as e:
            return jsonify({'reply': f"Failed to reply: {e}"})
    # Forward latest email
    if "forward" in intent:
        try:
            # Get latest email
            results = service.users().messages().list(
                userId='me',
                maxResults=1,
                labelIds=['UNREAD', 'CATEGORY_PERSONAL', 'INBOX'],
                q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
            ).execute()
            messages = results.get('messages', [])
            if not messages:
                return jsonify({'reply': "No email found to forward."})
            msg_id = messages[0]['id']
            msg_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
            headers = msg_data['payload'].get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
            snippet = msg_data.get('snippet', '')
            # Use OpenAI to generate a forward body
            forward_prompt = f"Write a short message to forward this email:\nFrom: {sender}\nSubject: {subject}\nSnippet: {snippet}"
            forward_response = openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": forward_prompt}]
            )
            forward_body = forward_response.choices[0].message.content.strip()
            # For demo, forward to self (in production, parse recipient from intent)
            recipient = sender
            from email.mime.text import MIMEText
            import base64
            fwd_message = MIMEText(forward_body)
            fwd_message['to'] = recipient
            fwd_message['subject'] = "Fwd: " + subject
            raw = base64.urlsafe_b64encode(fwd_message.as_bytes()).decode()
            msg = {'raw': raw}
            service.users().messages().send(userId='me', body=msg).execute()
            return jsonify({'reply': "Email forwarded."})
        except Exception as e:
            return jsonify({'reply': f"Failed to forward: {e}"})
    # Default: echo intent
    return jsonify({'reply': f'Intent: {intent}'})

@app.route('/apricot-mailbox', methods=['GET'])
def apricot_mailbox():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'mailbox': [], 'error': 'Missing or invalid Authorization header'}), 401
    access_token = auth_header.split(' ')[1]
    service = get_gmail_service_from_token(access_token)
    try:
        results = service.users().messages().list(
            userId='me',
            labelIds=['CATEGORY_PERSONAL', 'INBOX'],
            maxResults=10,
            q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
        ).execute()
        messages = results.get('messages', [])
        mailbox = []
        for msg in messages:
            msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
            headers = msg_data['payload'].get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
            snippet = msg_data.get('snippet', '')
            mailbox.append({'id': msg['id'], 'subject': subject, 'sender': sender, 'snippet': snippet})
        return jsonify({'mailbox': mailbox})
    except Exception as e:
        return jsonify({'mailbox': [], 'error': str(e)})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True) 