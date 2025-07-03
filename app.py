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
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from difflib import get_close_matches
from collections import defaultdict
from functools import lru_cache
import time
import json

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

# Add a persistent cache for email categories
CATEGORY_CACHE_FILE = 'email_category_cache.json'
try:
    with open(CATEGORY_CACHE_FILE, 'r') as f:
        EMAIL_CATEGORY_CACHE = json.load(f)
except Exception:
    EMAIL_CATEGORY_CACHE = {}

def save_category_cache():
    with open(CATEGORY_CACHE_FILE, 'w') as f:
        json.dump(EMAIL_CATEGORY_CACHE, f)

def get_gmail_service():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    service = build("gmail", "v1", credentials=creds)
    return service


def get_gmail_service_from_token(access_token):
    credentials = Credentials(token=access_token, scopes=SCOPES)
    service = build('gmail', 'v1', credentials=credentials)
    return service


def get_user_name_from_gmail(access_token):
    """Get the user's actual name from Gmail profile"""
    try:
        credentials = Credentials(token=access_token, scopes=SCOPES)
        service = build('gmail', 'v1', credentials=credentials)
        profile = service.users().getProfile(userId='me').execute()
        return profile.get('emailAddress', 'Gmail User')
    except Exception as e:
        print(f'[EMAIL ASSISTANT] Error getting user name: {e}')
        return 'Gmail User'


@lru_cache(maxsize=2000)
def categorize_email_openai(subject, sender, snippet):
    prompt = f"""
    Classify this email into one of: Urgent, Important, Promotion, Spam, Misc.
    Urgent = needs attention before end of day.
    Email:
    Subject: {subject}
    From: {sender}
    Snippet: {snippet}
    Category:
    """
    try:
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
        )
        category = response.choices[0].message.content.strip().split("\n")[0]
        category = category.capitalize()
        if category not in ["Urgent", "Important", "Promotion", "Spam", "Misc"]:
            return "Misc"
        return category
    except Exception as e:
        print(f"[EMAIL ASSISTANT] Categorization error: {e}")
        return "Misc"


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
        search_url = (
            f'https://html.duckduckgo.com/html/?q={requests.utils.quote(command)}'
        )
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
        return jsonify({'reply': 'Missing or invalid Authorization header',
                       'speak': 'Missing or invalid Authorization header'}), 401
    access_token = auth_header.split(' ')[1]
    service = get_gmail_service_from_token(access_token)
    data = request.get_json()
    command = data.get('command', '')
    print(f'[EMAIL ASSISTANT] Received command: {command}')
    if not command:
        print('[EMAIL ASSISTANT] No command received')
        return jsonify({'reply': "No command received.",
                       'speak': "No command received."}), 400

    # Check for pending action (confirmation flow)
    session = pending_actions[access_token]
    if session.get('pending'):
        # User is confirming or clarifying
        if session['pending'] == 'confirm_recipient':
            user_reply = command.strip().lower()
            matches = session['matches']
            current_index = session.get('current_index', 0)

            if user_reply in ['yes', 'confirm', 'correct', 'right']:
                # User confirmed this recipient - extract email from "Name
                # <email>" format
                recipient_full = matches[current_index]
                if '<' in recipient_full and '>' in recipient_full:
                    recipient = recipient_full.split('<')[1].split('>')[
                        0]  # Extract email
                else:
                    recipient = recipient_full  # Fallback

                session['recipient'] = recipient
                if session['action'] == 'send':
                    session['pending'] = 'ask_subject'
                    return jsonify(
                        {
                            'reply': f"What should be the subject of the email to {recipient_full}?",
                            'speak': f"What should be the subject of the email to {recipient_full}?",
                            'pending': 'ask_subject'})
                elif session['action'] == 'forward':
                    session['pending'] = 'confirm_message'
                    # Get latest email
                    results = service.users().messages().list(
                        userId='me', maxResults=1, labelIds=['CATEGORY_PERSONAL', 'INBOX'],
                        q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
                    ).execute()
                    messages = results.get('messages', [])
                    if not messages:
                        del pending_actions[access_token]
                        return jsonify(
                            {'reply': "No email found to forward.", 'speak': "No email found to forward."})
                    msg_id = messages[0]['id']
                    msg_data = service.users().messages().get(
                        userId='me', id=msg_id, format='full').execute()
                    headers = msg_data['payload'].get('headers', [])
                    subject = next(
                        (h['value'] for h in headers if h['name'] == 'Subject'),
                        'No Subject'
                    )
                    sender = next(
                        (h['value'] for h in headers if h['name'] == 'From'),
                        'Unknown Sender'
                    )
                    snippet = msg_data.get('snippet', '')
                    user_name = get_user_name_from_gmail(access_token)
                    forward_prompt = (
                        f"Write a short message from {user_name} to forward this email:\nFrom: {sender}\nSubject: {subject}\nSnippet: {snippet}"
                    )
                    forward_response = openai_client.chat.completions.create(
                        model="gpt-3.5-turbo",
                        messages=[{"role": "user", "content": forward_prompt}]
                    )
                    forward_body = forward_response.choices[0].message.content.strip()
                    session['subject'] = "Fwd: " + subject
                    session['body'] = forward_body
                    reply = (
                        f"Ready to send this email to {recipient_full}:\nSubject: "
                        f"{session['subject']}\nBody: {session['body']}\n"
                        "Say 'yes' to send or 'no' to cancel."
                    )  # noqa: E501
                    return jsonify(
                        {'reply': reply, 'speak': reply, 'pending': 'confirm_message'})
            elif user_reply in ['no', 'nope', 'wrong', 'incorrect']:
                # Try next match
                next_index = current_index + 1
                if next_index < len(matches):
                    session['current_index'] = next_index
                    reply = f"Did you mean {matches[next_index]}? Say yes or no."
                    return jsonify({'reply': reply, 'speak': reply, 'pending': 'confirm_recipient'})
                else:
                    # No more matches
                    del pending_actions[access_token]
                    return jsonify(
                        {
                            'reply': f"No more matches found for '{session.get('recipient_query', '')}'. Please try a different name.",
                            'speak': "No more matches found. Please try a different name."
                        }
                    )
            else:
                # Unclear response, ask again
                reply = f"Did you mean {matches[current_index]}? Please say yes or no."
                return jsonify({'reply': reply, 'speak': reply,
                               'pending': 'confirm_recipient'})
        elif session['pending'] == 'ask_subject':
            session['subject'] = command.strip()
            session['pending'] = 'ask_body'
            return jsonify(
                {
                    'reply': f"What should be the content of the email to {session['recipient']}?",
                    'speak': f"What should be the content of the email to {session['recipient']}?",
                    'pending': 'ask_body'
                }
            )
        elif session['pending'] == 'ask_body':
            user_topic = command.strip()
            session['pending'] = 'confirm_message'
            user_name = get_user_name_from_gmail(access_token)

            # Use ChatGPT to write a proper email body based on the topic
            body_prompt = (
                f"Write a professional, friendly email from {user_name} to {session['recipient']}.\n\n"
                f"Topic/Context: {user_topic}\n"
                f"Subject: {session['subject']}\n\n"
                f"Requirements:\n"
                "- Write a complete, well-structured email\n"
                "- Be professional but friendly\n"
                "- Include a proper greeting and closing\n"
                "- Make it sound natural and personal\n"
                "- Keep it concise but complete\n"
                "- Use the topic as the main content of the email\n\n"
                "Write the email body:"
            )

            body_response = openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": body_prompt}]
            )
            session['body'] = body_response.choices[0].message.content.strip()
            reply = (
                f"Ready to send this email to {session['recipient']}:\nSubject: "
                f"{session['subject']}\nBody: {session['body']}\n"
                "Say 'yes' to send or 'no' to cancel."
            )  # noqa: E501
            return jsonify({
                'reply': reply,
                'speak': reply,
                'pending': 'confirm_message'
            })  # noqa: E501
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
                return jsonify(
                    {
                        'reply': f"Email sent to {session['recipient']}.",
                        'speak': f"Email sent to {session['recipient']}."
                    }
                )
            else:
                del pending_actions[access_token]
                return jsonify({'reply': "Cancelled sending email.",
                               'speak': "Cancelled sending email."})

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
                    return jsonify(
                        {
                            'reply': "You have no unread emails in your Primary inbox.",
                            'speak': "You have no unread emails in your Primary inbox."})
                summaries = []
                for msg in messages:
                    msg_data = service.users().messages().get(
                        userId='me', id=msg['id']).execute()
                    headers = msg_data['payload'].get('headers', [])
                    subject = next(
                        (h['value'] for h in headers if h['name'] == 'Subject'),
                        'No Subject'
                    )
                    sender = next(
                        (h['value'] for h in headers if h['name'] == 'From'),
                        'Unknown Sender'
                    )
                    summaries.append(f"Email from {sender}: {subject}")
                reply = '\n'.join(summaries)
                return jsonify({'reply': reply, 'speak': reply})
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (summarize unread): {e}')
                return jsonify({'reply': f"Failed to fetch emails: {e}",
                               'speak': f"Failed to fetch emails: {e}"})
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
                    return jsonify(
                        {'reply': "No email found to read.", 'speak': "No email found to read."})
                msg_id = messages[0]['id']
                msg_data = service.users().messages().get(
                    userId='me', id=msg_id, format='full').execute()
                headers = msg_data['payload'].get('headers', [])
                subject = next(
                    (h['value'] for h in headers if h['name'] == 'Subject'),
                    'No Subject'
                )
                sender = next(
                    (h['value'] for h in headers if h['name'] == 'From'),
                    'Unknown Sender'
                )
                snippet = msg_data.get('snippet', '')
                reply = f"From {sender}. Subject: {subject}. Snippet: {snippet}"
                return jsonify({'reply': reply, 'speak': reply})
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (read my latest): {e}')
                return jsonify(
                    {'reply': f"Failed to read email: {e}", 'speak': f"Failed to read email: {e}"})
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
                    return jsonify(
                        {'reply': "No email found to archive.", 'speak': "No email found to archive."})
                msg_id = messages[0]['id']
                service.users().messages().modify(
                    userId='me', id=msg_id, body={
                        'removeLabelIds': ['INBOX']}).execute()
                return jsonify({'reply': "Email archived.",
                               'speak': "Email archived."})
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (archive): {e}')
                return jsonify({'reply': f"Failed to archive: {e}",
                               'speak': f"Failed to archive: {e}"})
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
                    return jsonify(
                        {'reply': "No email found to delete.", 'speak': "No email found to delete."})
                msg_id = messages[0]['id']
                service.users().messages().trash(userId='me', id=msg_id).execute()
                return jsonify({'reply': "Email moved to Trash.",
                               'speak': "Email moved to Trash."})
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (delete): {e}')
                return jsonify({'reply': f"Failed to delete: {e}",
                               'speak': f"Failed to delete: {e}"})
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
                    return jsonify(
                        {'reply': "No email found to reply to.", 'speak': "No email found to reply to."})
                msg_id = messages[0]['id']
                msg_data = service.users().messages().get(
                    userId='me', id=msg_id, format='full').execute()
                headers = msg_data['payload'].get('headers', [])
                subject = next(
                    (h['value'] for h in headers if h['name'] == 'Subject'),
                    'No Subject'
                )
                sender = next(
                    (h['value'] for h in headers if h['name'] == 'From'),
                    'Unknown Sender'
                )
                snippet = msg_data.get('snippet', '')
                user_name = get_user_name_from_gmail(access_token)
                reply_prompt = f"Write a short, polite reply to this email from {user_name}:\nFrom: {sender}\nSubject: {subject}\nSnippet: {snippet}"
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
                return jsonify(
                    {'reply': "Reply sent.", 'speak': "Reply sent."})
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (reply): {e}')
                return jsonify({'reply': f"Failed to reply: {e}",
                               'speak': f"Failed to reply: {e}"})
        # Forward my latest email to [name]
        if 'forward my latest email to' in command.lower():
            try:
                # Extract recipient using OpenAI with better prompting
                extract_prompt = (
                    f"Extract the recipient's name from this command: '{command}'\n\n"
                    "Rules:\n"
                    "- Return ONLY the first name or full name of the person\n"
                    "- If it's a full name like 'John Smith', return 'John Smith'\n"
                    "- If it's just a first name like 'John', return 'John'\n"
                    "- Don't include email addresses, just the name\n"
                    "- Clean up any extra words or punctuation\n\n"
                    f"Command: {command}\nRecipient name:"
                )  # noqa: E501
                extract_response = openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": extract_prompt}]
                )
                recipient_query = extract_response.choices[0].message.content.strip(
                )

                # Search contacts in mailbox and build clean contact list
                results = service.users().messages().list(
                    userId='me', maxResults=100, q='').execute()
                messages = results.get('messages', [])
                contacts_dict = {}  # name -> primary email

                for msg in messages:
                    msg_data = service.users().messages().get(
                        userId='me',
                        id=msg['id'],
                        format='metadata',
                        metadataHeaders=['From', 'To']
                    ).execute()
                    for h in msg_data['payload'].get('headers', []):
                        if h['name'] in ['From', 'To']:
                            email = h['value']
                            # Extract name from email format: "John Doe
                            # <john@example.com>" or just "john@example.com"
                            if '<' in email and '>' in email:
                                # Format: "John Doe <john@example.com>"
                                name_part = email.split('<')[0].strip()
                                email_part = email.split('<')[1].split('>')[0]
                            else:
                                # Format: "john@example.com"
                                email_part = email
                                # Use username as name
                                name_part = email.split('@')[0]

                            # Clean up name (remove quotes, extra spaces)
                            name_part = name_part.strip().strip('"').strip("'")
                            if name_part and '@' not in name_part:  # Valid name
                                # Use the first email we find for each name
                                if name_part not in contacts_dict:
                                    contacts_dict[name_part] = email_part

                # Use ChatGPT to find the best matches
                match_prompt = (
                    f"I'm looking for a person named \"{recipient_query}\" in my contacts.\n\n"
                    f"Available contacts:\n"
                    f"{chr(10).join([f'- {name} <{email}>' for name, email in contacts_dict.items()])}\n\n"
                    "Find the best matches for \"{recipient_query}\". Consider:\n"
                    "- Exact name matches\n"
                    "- Similar first names\n"
                    "- Common nicknames\n"
                    "- Partial matches\n\n"
                    "Return ONLY the full contact entries (name <email>) that match, one per line.\n"
                    "If no good matches, return \"NO_MATCH\"."
                )

                match_response = openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": match_prompt}]
                )

                match_result = match_response.choices[0].message.content.strip(
                )
                if match_result == "NO_MATCH":
                    return jsonify(
                        {
                            'reply': f"Couldn't find anyone named '{recipient_query}'. Please try a different name.",
                            'speak': f"Couldn't find anyone named '{recipient_query}'. Please try a different name."})

                # Parse ChatGPT's response to get matches
                matches = []
                for line in match_result.split('\n'):
                    line = line.strip()
                    if line.startswith('- '):
                        line = line[2:]  # Remove "- " prefix
                    if '<' in line and '>' in line:
                        matches.append(line)

                if not matches:
                    return jsonify(
                        {
                            'reply': f"Couldn't find anyone named '{recipient_query}'. Please try a different name.",
                            'speak': f"Couldn't find anyone named '{recipient_query}'. Please try a different name."})

                # Start with first match
                pending_actions[access_token] = {
                    'pending': 'confirm_recipient',
                    'matches': matches,
                    'current_index': 0,
                    'action': 'forward',
                    'original_command': command,
                    'recipient_query': recipient_query
                }
                user_name = get_user_name_from_gmail(access_token)
                forward_prompt = (
                    f"Write a short message from {user_name} to forward this email:\nFrom: {sender}\nSubject: {subject}\nSnippet: {snippet}"
                )
                forward_response = openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": forward_prompt}]
                )
                forward_body = forward_response.choices[0].message.content.strip()
                session['subject'] = "Fwd: " + subject
                session['body'] = forward_body
                reply = f"Did you mean {matches[0]}? Say yes or no."
                return jsonify({'reply': reply, 'speak': reply,
                               'pending': 'confirm_recipient'})
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (forward to): {e}')
                return jsonify({'reply': f"Failed to forward: {e}",
                               'speak': f"Failed to forward: {e}"})
        # Send an email to [name]
        if 'send an email to' in command.lower():
            try:
                # Extract recipient using OpenAI with better prompting
                extract_prompt = (
                    f"Extract the recipient's name from this command: '{command}'\n\n"
                    "Rules:\n"
                    "- Return ONLY the first name or full name of the person\n"
                    "- If it's a full name like 'John Smith', return 'John Smith'\n"
                    "- If it's just a first name like 'John', return 'John'\n"
                    "- Don't include email addresses, just the name\n"
                    "- Clean up any extra words or punctuation\n\n"
                    f"Command: {command}\nRecipient name:"
                )  # noqa: E501
                extract_response = openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": extract_prompt}]
                )
                recipient_query = extract_response.choices[0].message.content.strip(
                )

                # Search contacts in mailbox and build clean contact list
                results = service.users().messages().list(
                    userId='me', maxResults=100, q='').execute()
                messages = results.get('messages', [])
                contacts_dict = {}  # name -> primary email

                for msg in messages:
                    msg_data = service.users().messages().get(
                        userId='me',
                        id=msg['id'],
                        format='metadata',
                        metadataHeaders=['From', 'To']
                    ).execute()
                    for h in msg_data['payload'].get('headers', []):
                        if h['name'] in ['From', 'To']:
                            email = h['value']
                            # Extract name from email format: "John Doe
                            # <john@example.com>" or just "john@example.com"
                            if '<' in email and '>' in email:
                                # Format: "John Doe <john@example.com>"
                                name_part = email.split('<')[0].strip()
                                email_part = email.split('<')[1].split('>')[0]
                            else:
                                # Format: "john@example.com"
                                email_part = email
                                # Use username as name
                                name_part = email.split('@')[0]

                            # Clean up name (remove quotes, extra spaces)
                            name_part = name_part.strip().strip('"').strip("'")
                            if name_part and '@' not in name_part:  # Valid name
                                # Use the first email we find for each name
                                if name_part not in contacts_dict:
                                    contacts_dict[name_part] = email_part

                # Use ChatGPT to find the best matches
                match_prompt = (
                    f"I'm looking for a person named \"{recipient_query}\" in my contacts.\n\n"
                    f"Available contacts:\n"
                    f"{chr(10).join([f'- {name} <{email}>' for name, email in contacts_dict.items()])}\n\n"
                    "Find the best matches for \"{recipient_query}\". Consider:\n"
                    "- Exact name matches\n"
                    "- Similar first names\n"
                    "- Common nicknames\n"
                    "- Partial matches\n\n"
                    "Return ONLY the full contact entries (name <email>) that match, one per line.\n"
                    "If no good matches, return \"NO_MATCH\"."
                )

                match_response = openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": match_prompt}]
                )

                match_result = match_response.choices[0].message.content.strip(
                )
                if match_result == "NO_MATCH":
                    return jsonify(
                        {
                            'reply': f"Couldn't find anyone named '{recipient_query}'. Please try a different name.",
                            'speak': f"Couldn't find anyone named '{recipient_query}'. Please try a different name."})

                # Parse ChatGPT's response to get matches
                matches = []
                for line in match_result.split('\n'):
                    line = line.strip()
                    if line.startswith('- '):
                        line = line[2:]  # Remove "- " prefix
                    if '<' in line and '>' in line:
                        matches.append(line)

                if not matches:
                    return jsonify(
                        {
                            'reply': f"Couldn't find anyone named '{recipient_query}'. Please try a different name.",
                            'speak': f"Couldn't find anyone named '{recipient_query}'. Please try a different name."})

                # Start with first match
                pending_actions[access_token] = {
                    'pending': 'confirm_recipient',
                    'matches': matches,
                    'current_index': 0,
                    'action': 'send',
                    'original_command': command,
                    'recipient_query': recipient_query
                }
                user_name = get_user_name_from_gmail(access_token)
                body_prompt = (
                    f"Write a short, friendly email from {user_name} to {recipient} about what the user just said: "
                    f"'{session['original_command']}'."
                )
                reply = f"Did you mean {matches[0]}? Say yes or no."
                return jsonify({
                    'reply': reply,
                    'speak': reply,
                    'pending': 'confirm_recipient'
                })  # noqa: E501
            except Exception as e:
                print(f'[EMAIL ASSISTANT] Error (send email): {e}')
                return jsonify(
                    {'reply': f"Failed to send email: {e}", 'speak': f"Failed to send email: {e}"})
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
                return jsonify({'reply': f"Failed to count unread emails: {e}",
                               'speak': f"Failed to count unread emails: {e}"})
        # Default: echo intent
        print(f'[EMAIL ASSISTANT] Default intent: {intent}')
        return jsonify({'reply': f'Intent: {intent}',
                       'speak': f'Intent: {intent}'})
    except Exception as e:
        print(f'[EMAIL ASSISTANT] Fatal error: {e}')
        return jsonify({'reply': f'Fatal error: {e}',
                       'speak': f'Fatal error: {e}'})


@app.route('/apricot-mailbox', methods=['GET'])
def apricot_mailbox():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify(
            {'mailbox': [], 'error': 'Missing or invalid Authorization header'}), 401
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
            msg_data = service.users().messages().get(
                userId='me', id=msg['id']).execute()
            headers = msg_data['payload'].get('headers', [])
            subject = next(
                (h['value'] for h in headers if h['name'] == 'Subject'),
                'No Subject'
            )
            sender = next(
                (h['value'] for h in headers if h['name'] == 'From'),
                'Unknown Sender'
            )
            recipient = next(
                (h['value'] for h in headers if h['name'] == 'To'),
                'Unknown Recipient'
            )
            snippet = msg_data.get('snippet', '')
            # Categorize
            category = categorize_email_openai(subject, sender, snippet)
            mailbox.append({'id': msg['id'],
                            'subject': subject,
                            'sender': sender,
                            'recipient': recipient,
                            'snippet': snippet,
                            'category': category})
        return jsonify({'mailbox': mailbox})
    except Exception as e:
        print("Gmail API error:", e)  # DEBUG
        return jsonify({'mailbox': [], 'error': str(e)})


@app.route('/apricot-categorized-mailbox', methods=['GET'])
def apricot_categorized_mailbox():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'mailbox': [], 'error': 'Missing or invalid Authorization header'}), 401
    access_token = auth_header.split(' ')[1]
    service = get_gmail_service_from_token(access_token)
    try:
        results = service.users().messages().list(
            userId='me',
            labelIds=['CATEGORY_PERSONAL', 'INBOX'],
            maxResults=1000,
            q='-category:promotions -category:social -category:updates -category:forums -in:spam -in:trash'
        ).execute()
        messages = results.get('messages', [])
        mailbox = []
        uncategorized = []
        for msg in messages:
            msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
            headers = msg_data['payload'].get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
            recipient = next((h['value'] for h in headers if h['name'] == 'To'), 'Unknown Recipient')
            snippet = msg_data.get('snippet', '')
            mailbox.append({'id': msg['id'], 'subject': subject, 'sender': sender, 'recipient': recipient, 'snippet': snippet})
            if msg['id'] not in EMAIL_CATEGORY_CACHE:
                uncategorized.append({'id': msg['id'], 'subject': subject, 'sender': sender, 'snippet': snippet})
        # Batch categorize uncategorized emails in chunks
        for i in range(0, len(uncategorized), 50):
            batch_categorize_emails_openai(uncategorized[i:i+50])
        # Attach category to each email
        for email in mailbox:
            email['category'] = EMAIL_CATEGORY_CACHE.get(email['id'], 'Misc')
        return jsonify({'mailbox': mailbox})
    except Exception as e:
        print("Gmail API error:", e)
        return jsonify({'mailbox': [], 'error': str(e)})


# Batch categorize emails using OpenAI

def batch_categorize_emails_openai(email_list):
    prompt = """
You are an expert email assistant. Categorize each email as one of: Urgent, Important, Promotion, Spam, Misc.
Urgent = needs attention before end of day. Important = work, personal, bills, or relevant. Promotion = marketing, offers, newsletters. Spam = scams, phishing, junk. Misc = anything else.

For each email, reply with just the category (one of: Urgent, Important, Promotion, Spam, Misc) on a new line, in the same order as the emails provided.

Emails:
"""
    for i, email in enumerate(email_list):
        prompt += f"\nEmail {i+1}:\nSubject: {email['subject']}\nFrom: {email['sender']}\nSnippet: {email['snippet']}"
    prompt += "\nCategories:"
    try:
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
        )
        categories = [c.strip().capitalize() for c in response.choices[0].message.content.strip().split('\n') if c.strip()]
        # Fallback if OpenAI returns less than expected
        if len(categories) != len(email_list):
            categories += ["Misc"] * (len(email_list) - len(categories))
        for i, email in enumerate(email_list):
            cat = categories[i] if categories[i] in ["Urgent", "Important", "Promotion", "Spam", "Misc"] else "Misc"
            EMAIL_CATEGORY_CACHE[email['id']] = cat
        save_category_cache()
    except Exception as e:
        print(f"[EMAIL ASSISTANT] Batch categorization error: {e}")
        # Fallback: keyword-based
        for email in email_list:
            subj = email['subject'].lower()
            if any(word in subj for word in ["invoice", "payment due", "asap", "urgent", "today", "immediately"]):
                EMAIL_CATEGORY_CACHE[email['id']] = "Urgent"
            elif any(word in subj for word in ["offer", "sale", "discount", "deal", "newsletter"]):
                EMAIL_CATEGORY_CACHE[email['id']] = "Promotion"
            elif any(word in subj for word in ["spam", "lottery", "prize", "winner", "phishing"]):
                EMAIL_CATEGORY_CACHE[email['id']] = "Spam"
            elif any(word in subj for word in ["meeting", "project", "update", "reminder", "bill", "statement"]):
                EMAIL_CATEGORY_CACHE[email['id']] = "Important"
            else:
                EMAIL_CATEGORY_CACHE[email['id']] = "Misc"
        save_category_cache()


# --- Robust recipient extraction for send/forward ---
def extract_recipient_name(command):
    prompt = f"""
    Extract the recipient's name from this command: '{command}'
    Only return the name, not the email address or extra words.
    """
    try:
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
        )
        name = response.choices[0].message.content.strip().split('\n')[0]
        return name
    except Exception as e:
        print(f"[EMAIL ASSISTANT] Recipient extraction error: {e}")
        return None


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
