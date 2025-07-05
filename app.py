from flask import Flask, request, jsonify, redirect, session, url_for
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
from google_auth_oauthlib.flow import InstalledAppFlow, Flow
from google.auth.transport.requests import Request
import pathlib
import pickle
from functools import lru_cache
import time

app = Flask(__name__)
# DEBUG: Allow all origins for CORS (for troubleshooting only)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

openai_client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
logging.basicConfig(level=logging.INFO)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.compose"
]

REDIRECT_URI = "https://voice-email-backend.onrender.com/oauth2callback"  # Update if your backend URL changes

CATEGORY_LABELS = ["Urgent", "Important", "Promotion", "Spam", "Misc"]
CATEGORY_KEYWORDS = {
    "Urgent": ["asap", "urgent", "immediately", "action required", "important update", "critical"],
    "Important": ["important", "please review", "attention", "reminder", "follow up"],
    "Promotion": ["sale", "discount", "offer", "deal", "promotion", "buy now", "limited time"],
    "Spam": ["lottery", "prize", "winner", "free", "click here", "unsubscribe", "congratulations", "claim now"],
}

# Simple in-memory cache for categorization results (per user)
_categorized_cache = {}
_CACHE_TTL = 300  # seconds

def _cache_key(user_id):
    return f"categorized:{user_id}"

def _get_cached_categories(user_id):
    entry = _categorized_cache.get(_cache_key(user_id))
    if entry and (time.time() - entry["ts"] < _CACHE_TTL):
        return entry["data"]
    return None

def _set_cached_categories(user_id, data):
    _categorized_cache[_cache_key(user_id)] = {"data": data, "ts": time.time()}

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
    creds = Credentials(token=access_token)
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

@app.route("/login-gmail")
def login_gmail():
    flow = Flow.from_client_secrets_file(
        "credentials.json",
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )
    session["state"] = state
    return redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session["state"]
    flow = Flow.from_client_secrets_file(
        "credentials.json",
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    # Save credentials for the user (for demo, just save to token.json)
    with open("token.json", "w") as token:
        token.write(credentials.to_json())
    return "Gmail login successful! You can close this tab and return to the app."

def categorize_email_openai(subject, snippet):
    prompt = (
        "Categorize the following email as one of: Urgent, Important, Promotion, Spam, Misc. "
        "Reply ONLY with the category name.\n"
        f"Subject: {subject}\nSnippet: {snippet}"
    )
    try:
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
        )
        category = response.choices[0].message.content.strip()
        if category in CATEGORY_LABELS:
            return category
    except Exception:
        pass
    return None

def categorize_email_keywords(subject, snippet):
    text = f"{subject} {snippet}".lower()
    for cat, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return cat
    return "Misc"

@app.route('/apricot-categorized-mailbox', methods=['GET'])
def apricot_categorized_mailbox():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'mailbox': {}, 'error': 'Missing or invalid Authorization header'}), 401
    access_token = auth_header.split(' ')[1]
    service = get_gmail_service_from_token(access_token)
    user_id = 'me'  # For demo, always 'me'.
    # Check cache
    cached = _get_cached_categories(user_id)
    if cached:
        return jsonify({'mailbox': cached, 'cached': True})
    try:
        results = service.users().messages().list(
            userId=user_id,
            labelIds=['CATEGORY_PERSONAL', 'INBOX'],
            maxResults=20,
            q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
        ).execute()
        messages = results.get('messages', [])
        categorized = {cat: [] for cat in CATEGORY_LABELS}
        for msg in messages:
            msg_data = service.users().messages().get(userId=user_id, id=msg['id']).execute()
            headers = msg_data['payload'].get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
            recipient = next((h['value'] for h in headers if h['name'] == 'To'), 'Unknown Recipient')
            snippet = msg_data.get('snippet', '')
            # Try OpenAI categorization, fallback to keywords
            category = categorize_email_openai(subject, snippet)
            if not category:
                category = categorize_email_keywords(subject, snippet)
            if category not in CATEGORY_LABELS:
                category = "Misc"
            categorized[category].append({
                'id': msg['id'],
                'subject': subject,
                'sender': sender,
                'recipient': recipient,
                'snippet': snippet
            })
        _set_cached_categories(user_id, categorized)
        return jsonify({'mailbox': categorized, 'cached': False})
    except Exception as e:
        return jsonify({'mailbox': {}, 'error': str(e)})

@app.route('/exchange-code', methods=['POST'])
def exchange_code():
    data = request.get_json()
    code = data.get('code')
    # Use the same redirect_uri as in Google Cloud Console
    redirect_uri = data.get('redirect_uri') or 'https://precort-c9846.web.app'
    if not code:
        return jsonify({'error': 'Missing code'}), 400
    try:
        flow = Flow.from_client_secrets_file(
            'credentials.json',
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        flow.fetch_token(code=code)
        credentials = flow.credentials
        return jsonify({
            'access_token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'expires_in': credentials.expiry.timestamp() if credentials.expiry else None,
            'token_type': credentials.token_uri
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True) 
