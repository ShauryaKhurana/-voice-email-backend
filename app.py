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
from difflib import get_close_matches
from collections import defaultdict

app = Flask(__name__)
CORS(app)  # Allow all origins for development

openai_client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
logging.basicConfig(level=logging.INFO)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.compose"
]

# In-memory session state (for demo; use Redis or DB for production)
pending_actions = defaultdict(dict)

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
        print('[EMAIL ASSISTANT] Missing or invalid Authorization header')
        return jsonify({'reply': 'Missing or invalid Authorization header', 'speak': 'Missing or invalid Authorization header'}), 401
    access_token = auth_header.split(' ')[1]
    service = get_gmail_service_from_token(access_token)
    data = request.get_json()
    command = data.get('command', '')
    print(f'[EMAIL ASSISTANT] Received command: {command}')
    if not command:
        print('[EMAIL ASSISTANT] No command received')
        return jsonify({'reply': "No command received.", 'speak': "No command received."}), 400

    # Check for pending action (confirmation flow)
    session = pending_actions[access_token]
    if session.get('pending'):
        # User is confirming or clarifying
        if session['pending'] == 'confirm_recipient':
            user_reply = command.strip().lower()
            matches = session['matches']
            if user_reply.isdigit() and 1 <= int(user_reply) <= len(matches):
                recipient = matches[int(user_reply)-1]
            else:
                recipient = next((m for m in matches if user_reply in m.lower()), None)
            if not recipient:
                del pending_actions[access_token]
                return jsonify({'reply': 'Could not match that contact. Please try again.', 'speak': 'Could not match that contact. Please try again.'})
            session['recipient'] = recipient
            if session['action'] == 'send':
                session['pending'] = 'ask_subject'
                return jsonify({'reply': f"What should be the subject of the email to {recipient}?", 'speak': f"What should be the subject of the email to {recipient}?", 'pending': 'ask_subject'})
            elif session['action'] == 'forward':
                session['pending'] = 'confirm_message'
                # Get latest email
                results = service.users().messages().list(
                    userId='me', maxResults=1, labelIds=['CATEGORY_PERSONAL', 'INBOX'],
                    q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash').execute()
                messages = results.get('messages', [])
                if not messages:
                    del pending_actions[access_token]
                    return jsonify({'reply': "No email found to forward.", 'speak': "No email found to forward."})
                msg_id = messages[0]['id']
                msg_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
                headers = msg_data['payload'].get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
                snippet = msg_data.get('snippet', '')
                forward_prompt = f"Write a short message to forward this email:\nFrom: {sender}\nSubject: {subject}\nSnippet: {snippet}"
                forward_response = openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": forward_prompt}]
                )
                forward_body = forward_response.choices[0].message.content.strip()
                session['subject'] = "Fwd: " + subject
                session['body'] = forward_body
                reply = f"Ready to send this email to {recipient}:\nSubject: {session['subject']}\nBody: {session['body']}\nSay 'yes' to send or 'no' to cancel."
                return jsonify({'reply': reply, 'speak': reply, 'pending': 'confirm_message'})
        elif session['pending'] == 'ask_subject':
            session['subject'] = command.strip()
            session['pending'] = 'ask_body'
            return jsonify({'reply': f"What should be the content of the email to {session['recipient']}?", 'speak': f"What should be the content of the email to {session['recipient']}?", 'pending': 'ask_body'})
        elif session['pending'] == 'ask_body':
            session['body'] = command.strip()
            session['pending'] = 'confirm_message'
            reply = f"Ready to send this email to {session['recipient']}:\nSubject: {session['subject']}\nBody: {session['body']}\nSay 'yes' to send or 'no' to cancel."
            return jsonify({'reply': reply, 'speak': reply, 'pending': 'confirm_message'})
        elif session['pending'] == 'confirm_message':
            user_reply = command.strip().lower()
            if user_reply in ['yes', 'send', 'confirm', 'okay', 'ok']:
                from email.mime.text import MIMEText
                import base64
                message = MIMEText(session['body'])
                message['to'] = session['recipient']
                message['subject'] = session['subject']
                raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
                msg = {'raw': raw}
                service.users().messages().send(userId='me', body=msg).execute()
                del pending_actions[access_token]
                return jsonify({'reply': f"Email sent to {session['recipient']}.", 'speak': f"Email sent to {session['recipient']}."})
            else:
                del pending_actions[access_token]
                return jsonify({'reply': "Cancelled sending email.", 'speak': "Cancelled sending email."})

    supported = [
        'summarize unread emails',
        'read my latest email',
        'archive my latest email',
        'delete my latest email',
        'reply to my latest email',
        'forward my latest email to [name]',
        'summarize my inbox',
        'how many unread emails do I have',
        'send an email to [name]',
    ]
    cmd_lc = command.lower()
    match = get_close_matches(cmd_lc, supported, n=1, cutoff=0.5)
    intent = match[0] if match else cmd_lc
    print(f'[EMAIL ASSISTANT] Matched intent: {intent}')

    try:
        # Summarize unread emails
        if 'summarize unread' in intent or 'summarize my inbox' in intent:
            try:
                results = service.users().messages().list(
                    userId='me',
                    labelIds=['UNREAD', 'CATEGORY_PERSONAL', 'INBOX'],
                    maxResults=5,
                    q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
                ).execute()
                messages = results.get('messages', [])
                if not messages:
                    return jsonify({'reply': "You have no unread emails in your Primary inbox.", 'speak': "You have no unread emails in your Primary inbox."})
                summaries = []
                for msg in messages:
                    msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
                    headers = msg_data['payload'].get('headers', [])
                    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                    sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
                    summaries.append(f"Email from {sender}: {subject}")
                reply = '\n'.join(summaries)
                return jsonify({'reply': reply, 'speak': reply})
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (summarize unread): {e}')
                return jsonify({'reply': f"Failed to fetch emails: {e}", 'speak': f"Failed to fetch emails: {e}"})
        # Read my latest email
        if 'read my latest' in intent:
            try:
                results = service.users().messages().list(
                    userId='me',
                    maxResults=1,
                    labelIds=['CATEGORY_PERSONAL', 'INBOX'],
                    q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
                ).execute()
                messages = results.get('messages', [])
                if not messages:
                    return jsonify({'reply': "No email found to read.", 'speak': "No email found to read."})
                msg_id = messages[0]['id']
                msg_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
                headers = msg_data['payload'].get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
                snippet = msg_data.get('snippet', '')
                reply = f"From {sender}. Subject: {subject}. Snippet: {snippet}"
                return jsonify({'reply': reply, 'speak': reply})
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (read my latest): {e}')
                return jsonify({'reply': f"Failed to read email: {e}", 'speak': f"Failed to read email: {e}"})
        # Archive latest email
        if 'archive' in intent:
            try:
                results = service.users().messages().list(
                    userId='me',
                    maxResults=1,
                    labelIds=['CATEGORY_PERSONAL', 'INBOX'],
                    q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
                ).execute()
                messages = results.get('messages', [])
                if not messages:
                    return jsonify({'reply': "No email found to archive.", 'speak': "No email found to archive."})
                msg_id = messages[0]['id']
                service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['INBOX']}).execute()
                return jsonify({'reply': "Email archived.", 'speak': "Email archived."})
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (archive): {e}')
                return jsonify({'reply': f"Failed to archive: {e}", 'speak': f"Failed to archive: {e}"})
        # Delete latest email
        if 'delete' in intent or 'trash' in intent:
            try:
                results = service.users().messages().list(
                    userId='me',
                    maxResults=1,
                    labelIds=['CATEGORY_PERSONAL', 'INBOX'],
                    q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
                ).execute()
                messages = results.get('messages', [])
                if not messages:
                    return jsonify({'reply': "No email found to delete.", 'speak': "No email found to delete."})
                msg_id = messages[0]['id']
                service.users().messages().trash(userId='me', id=msg_id).execute()
                return jsonify({'reply': "Email moved to Trash.", 'speak': "Email moved to Trash."})
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (delete): {e}')
                return jsonify({'reply': f"Failed to delete: {e}", 'speak': f"Failed to delete: {e}"})
        # Reply to latest email
        if 'reply' in intent:
            try:
                results = service.users().messages().list(
                    userId='me',
                    maxResults=1,
                    labelIds=['CATEGORY_PERSONAL', 'INBOX'],
                    q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
                ).execute()
                messages = results.get('messages', [])
                if not messages:
                    return jsonify({'reply': "No email found to reply to.", 'speak': "No email found to reply to."})
                msg_id = messages[0]['id']
                msg_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
                headers = msg_data['payload'].get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
                snippet = msg_data.get('snippet', '')
                reply_prompt = f"Write a short, polite reply to this email:\nFrom: {sender}\nSubject: {subject}\nSnippet: {snippet}"
                reply_response = openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": reply_prompt}]
                )
                reply_body = reply_response.choices[0].message.content.strip()
                from email.mime.text import MIMEText
                import base64
                message = MIMEText(reply_body)
                message['to'] = sender
                message['subject'] = "Re: " + subject
                raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
                msg = {'raw': raw, 'threadId': msg_id}
                service.users().messages().send(userId='me', body=msg).execute()
                return jsonify({'reply': "Reply sent.", 'speak': "Reply sent."})
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (reply): {e}')
                return jsonify({'reply': f"Failed to reply: {e}", 'speak': f"Failed to reply: {e}"})
        # Forward my latest email to [name]
        if 'forward my latest email to' in intent:
            try:
                # Extract recipient using OpenAI
                extract_prompt = f"Extract the recipient's email or name from this command: '{command}'. Reply with only the email or name, nothing else."
                extract_response = openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": extract_prompt}]
                )
                recipient_query = extract_response.choices[0].message.content.strip()
                # Search contacts in mailbox
                results = service.users().messages().list(userId='me', maxResults=50, q='').execute()
                messages = results.get('messages', [])
                contacts = set()
                for msg in messages:
                    msg_data = service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From', 'To']).execute()
                    for h in msg_data['payload'].get('headers', []):
                        if h['name'] in ['From', 'To']:
                            contacts.add(h['value'])
                matches = [c for c in contacts if recipient_query.lower() in c.lower()]
                if not matches:
                    pending_actions[access_token] = {}
                    return jsonify({'reply': f"Couldn't find anyone matching '{recipient_query}'. Please say the email address.", 'speak': f"Couldn't find anyone matching '{recipient_query}'. Please say the email address.", 'pending': 'confirm_recipient', 'matches': []})
                if len(matches) == 1:
                    # Proceed to confirmation
                    pending_actions[access_token] = {'pending': 'confirm_message', 'recipient': matches[0], 'action': 'forward', 'original_command': command}
                    return apricot_email_assistant()
                # Ask user to pick
                reply = "I found multiple contacts. Please say the number or email:\n" + '\n'.join([f"{i+1}. {m}" for i, m in enumerate(matches)])
                pending_actions[access_token] = {'pending': 'confirm_recipient', 'matches': matches, 'action': 'forward', 'original_command': command}
                return jsonify({'reply': reply, 'speak': reply, 'pending': 'confirm_recipient', 'matches': matches})
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (forward to): {e}')
                return jsonify({'reply': f"Failed to forward: {e}", 'speak': f"Failed to forward: {e}"})
        # Send an email to [name]
        if 'send an email to' in intent:
            try:
                # Extract recipient using OpenAI
                extract_prompt = f"Extract the recipient's email or name from this command: '{command}'. Reply with only the email or name, nothing else."
                extract_response = openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": extract_prompt}]
                )
                recipient_query = extract_response.choices[0].message.content.strip()
                # Search contacts in mailbox
                results = service.users().messages().list(userId='me', maxResults=50, q='').execute()
                messages = results.get('messages', [])
                contacts = set()
                for msg in messages:
                    msg_data = service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['From', 'To']).execute()
                    for h in msg_data['payload'].get('headers', []):
                        if h['name'] in ['From', 'To']:
                            contacts.add(h['value'])
                matches = [c for c in contacts if recipient_query.lower() in c.lower()]
                if not matches:
                    pending_actions[access_token] = {}
                    return jsonify({'reply': f"Couldn't find anyone matching '{recipient_query}'. Please say the email address.", 'speak': f"Couldn't find anyone matching '{recipient_query}'. Please say the email address.", 'pending': 'confirm_recipient', 'matches': []})
                if len(matches) == 1:
                    # Proceed to confirmation
                    pending_actions[access_token] = {'pending': 'confirm_message', 'recipient': matches[0], 'action': 'send', 'original_command': command}
                    return apricot_email_assistant()
                # Ask user to pick
                reply = "I found multiple contacts. Please say the number or email:\n" + '\n'.join([f"{i+1}. {m}" for i, m in enumerate(matches)])
                pending_actions[access_token] = {'pending': 'confirm_recipient', 'matches': matches, 'action': 'send', 'original_command': command}
                return jsonify({'reply': reply, 'speak': reply, 'pending': 'confirm_recipient', 'matches': matches})
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (send email): {e}')
                return jsonify({'reply': f"Failed to send email: {e}", 'speak': f"Failed to send email: {e}"})
        # How many unread emails
        if 'how many unread' in intent:
            try:
                results = service.users().messages().list(
                    userId='me',
                    labelIds=['UNREAD', 'CATEGORY_PERSONAL', 'INBOX'],
                    q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
                ).execute()
                messages = results.get('messages', [])
                count = len(messages)
                reply = f"You have {count} unread emails in your Primary inbox."
                return jsonify({'reply': reply, 'speak': reply})
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (how many unread): {e}')
                return jsonify({'reply': f"Failed to count unread emails: {e}", 'speak': f"Failed to count unread emails: {e}"})
        # Default: echo intent
        print(f'[EMAIL ASSISTANT] Default intent: {intent}')
        return jsonify({'reply': f'Intent: {intent}', 'speak': f'Intent: {intent}'})
    except Exception as e:
        print(f'[EMAIL ASSISTANT] Fatal error: {e}')
        return jsonify({'reply': f'Fatal error: {e}', 'speak': f'Fatal error: {e}'})

@app.route('/apricot-mailbox', methods=['GET'])
def apricot_mailbox():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'mailbox': [], 'error': 'Missing or invalid Authorization header'}), 401
    access_token = auth_header.split(' ')[1]
    print("Access token received:", access_token)  # DEBUG
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
        print("Gmail API error:", e)  # DEBUG
        return jsonify({'mailbox': [], 'error': str(e)})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True) 