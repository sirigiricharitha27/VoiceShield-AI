import os, json, uuid, re
import requests
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from dotenv import load_dotenv
from database import init_db, connect
from gnani_client import transcribe_audio, analyze_text, synthesize_speech, provider_status, GnaniNotConfigured

load_dotenv()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, os.getenv('UPLOAD_FOLDER', 'uploads'))
os.makedirs(UPLOAD_DIR, exist_ok=True)
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_UPLOAD_MB', '12')) * 1024 * 1024
CORS(app, origins=[os.getenv('FRONTEND_ORIGIN', 'http://localhost:5173')], supports_credentials=True)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-only-change-me')
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
init_db()

LANGUAGES = ['English', 'Telugu', 'Hindi', 'Tamil', 'Kannada', 'Malayalam']
GUIDANCE = {
 'IN_PROGRESS': [
  'Stop the interaction. Do not approve further collect requests, transfers or payment prompts.',
  'Contact your bank immediately using the number or channel on its official website/app. Ask about blocking or securing the affected account and transaction.',
  'For suspected financial cyber fraud in India, call 1930 as soon as possible and use cybercrime.gov.in.',
  'Do not share OTPs, PINs, passwords or screen-sharing access with anyone.'
 ],
 'ALREADY_HAPPENED': [
  'Contact your bank immediately through its official channel and report the unauthorized transaction.',
  'For suspected financial cyber fraud in India, call 1930 as soon as possible.',
  'Submit a complaint through cybercrime.gov.in and keep the acknowledgement/reference number.',
  'Preserve transaction references, messages, call details and screenshots. Do not delete relevant evidence.'
 ],
 'SUSPICIOUS_ATTEMPT': [
  'Do not click suspicious links or approve payment requests.',
  'Never share OTPs, UPI PINs, passwords or banking credentials.',
  'If you shared credentials or installed an app, contact your bank through its official channel and secure affected accounts.',
  'Report suspicious activity through the appropriate official cybercrime reporting channel.'
 ],
 'UNCLEAR': [
  'Do not share OTPs, PINs, passwords or banking credentials.',
  'Do not approve unexpected payment requests or click suspicious links.',
  'If money may have been transferred, contact your bank immediately and call 1930 for suspected financial cyber fraud in India.',
  'Review the incident details and add any missing information before preparing a complaint.'
 ]
}

def token_for(user_id): return serializer.dumps({'uid': user_id})
def current_user():
    auth = request.headers.get('Authorization', '')
    token = auth.replace('Bearer ', '', 1) if auth.startswith('Bearer ') else request.cookies.get('vs_session')
    if not token: return None
    try:
        data = serializer.loads(token, max_age=60*60*24*7)
    except (BadSignature, SignatureExpired): return None
    with connect() as db:
        row = db.execute('SELECT id,name,email,preferred_language,created_at FROM users WHERE id=?', (data.get('uid'),)).fetchone()
    return dict(row) if row else None

def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user: return jsonify({'error':'Please sign in to continue.'}), 401
        g.user = user
        return fn(*args, **kwargs)
    return wrapper

def incident_for_user(incident_id):
    with connect() as db:
        row = db.execute('SELECT * FROM incidents WHERE id=? AND user_id=?', (incident_id, g.user['id'])).fetchone()
        if not row: return None
        item = dict(row); item['analysis'] = json.loads(item.pop('analysis_json') or '{}')
        item['evidence'] = [dict(x) for x in db.execute('SELECT id,filename,mime_type,created_at FROM evidence WHERE incident_id=?', (incident_id,)).fetchall()]
        return item

def make_report(data):
    """Build an editable, evidence-aware complaint draft from saved incident data."""
    a = data.get('analysis') or {}
    transcript = data.get('transcript') or a.get('summary') or ''
    transcript_language = data.get('language') or 'Not specified'
    # Detect the dominant script in the saved transcript to guard against stale UI metadata.
    script_ranges = [
        ('Telugu', r'[\u0C00-\u0C7F]'), ('Hindi', r'[\u0900-\u097F]'),
        ('Tamil', r'[\u0B80-\u0BFF]'), ('Kannada', r'[\u0C80-\u0CFF]'),
        ('Malayalam', r'[\u0D00-\u0D7F]'),
    ]
    detected_scripts = sorted(
        [(name, len(re.findall(pattern, transcript))) for name, pattern in script_ranges],
        key=lambda item: item[1], reverse=True
    )
    if detected_scripts and detected_scripts[0][1] >= 3:
        transcript_language = detected_scripts[0][0]
    complaint_language = data.get('complaint_language') or 'English'
    evidence = data.get('evidence') if isinstance(data.get('evidence'), list) else []

    def money(value):
        if value in (None, ''):
            return 'Not confirmed — verify'
        try:
            return '₹' + format(float(str(value).replace(',', '')), ',.2f').rstrip('0').rstrip('.')
        except (TypeError, ValueError):
            return str(value)

    def lines(items, key):
        result = []
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                claim = str(item.get(key) or '').strip()
                quote = str(item.get('evidence_quote') or '').strip()
                if claim:
                    result.append(f'- {claim}' + (f' | Evidence: “{quote}”' if quote else ''))
            elif str(item).strip():
                result.append(f'- {str(item).strip()}')
        return '\n'.join(result) or '- Not identified — verify against the original description'

    def bullet(items):
        return '\n'.join(f'- {str(x)}' for x in items if str(x).strip()) if isinstance(items, list) and items else '- None identified'

    # Create separate, transcript-grounded exposure entries. Each quotation is
    # the smallest useful exact phrase from the complainant's original text.
    exposure_items = []
    source = transcript.casefold()
    entered_context = bool(re.search(
        r'\b(entered|typed|submitted|provided)\b|నమోదు చేశాను|నమోదు చేసాను',
        source, re.I
    ))

    exposure_patterns = [
        (
            'Name entered on the linked website — possible exposure',
            r'\b(?:my\s+)?(?:full\s+)?name\b|నా పేరు',
            r'\b(?:entered|typed|submitted)\s+(?:my\s+)?(?:full\s+)?name\b|నా పేరు'
        ),
        (
            'Mobile number entered on the linked website — possible exposure',
            r'\b(?:mobile|phone)\s+number\b|మొబైల్ నంబర్',
            r'\b(?:mobile|phone)\s+number\b|మొబైల్ నంబర్'
        ),
        (
            'Bank account number entered on the linked website — possible exposure',
            r'\b(?:bank\s+)?account\s+number\b|బ్యాంక్ ఖాతా నంబర్',
            r'\b(?:bank\s+)?account\s+number\b|బ్యాంక్ ఖాతా నంబర్'
        ),
    ]

    if entered_context:
        for label, presence_pattern, quote_pattern in exposure_patterns:
            if re.search(presence_pattern, transcript, re.I):
                quote_match = re.search(quote_pattern, transcript, re.I)
                if quote_match:
                    quote = quote_match.group(0).strip()
                    exposure_items.append(f'- {label} | Evidence: “{quote}”')

    # Preserve provider-detected exposures when no explicit entry could be
    # established from the transcript. These remain labelled as possible.
    if not exposure_items:
        exposure_items = [
            f'- {x.get("exposure")} | Evidence: “{x.get("evidence_quote", "")}”'
            for x in (a.get('security_exposures') or [])
            if isinstance(x, dict) and x.get('exposure')
        ]

    # A compact ordered event sequence. Events are included only when supported
    # by explicit words/phrases in the source; this is not an independently verified timeline.
    timeline_rules = [
        ('Contact received', r'(called|phone call|ఫోన్ చేశాడు|ఫోన్ చేసింది|కాల్ చేశాడు)'),
        ('Link received through a message', r'(whatsapp|వాట్సాప్).{0,100}(link|లింక్)|(link|లింక్).{0,100}(whatsapp|వాట్సాప్)'),
        ('Link opened/clicked', r'(clicked|opened the link|క్లిక్ చేశాను|క్లిక్ చేసి)'),
        ('Personal/banking details entered', r'(entered|typed|submitted|నమోదు చేశాను|నమోదు చేసాను)'),
        ('OTP requested by the website/caller', r'(otp.{0,50}(asked|requested|అడిగింది|అడిగారు)|(?:asked|requested|అడిగింది|అడిగారు).{0,50}otp)'),
        ('Money sent / transferred', r'(deducted|debited|transferred|sent|paid|transfer was successful|పంపించాను|బదిలీ చేశాను|కట్ అయ్యాయి)'),
        ('Payment demanded', r'(asked me to pay|demanded.{0,30}pay|payment request|collect request|చెల్లించమని అడిగారు)'),
        ('No suspicious activity reported', r'(no suspicious (?:transactions|activity|calls|messages)|ఎలాంటి అనుమానాస్పద)'),
        ('Payment refused / no transfer reported', r'(refused|did not pay|no money was (?:sent|transferred)|not transferred|నిరాకరించాను|డబ్బు బదిలీ చేయలేదు)'),
    ]
    timeline = []
    for label, pattern in timeline_rules:
        if re.search(pattern, transcript, re.I):
            timeline.append(f'- {label} (as described by the complainant)')
    payment_made = a.get('payment_made')
    payment_label = 'Yes' if payment_made is True else 'No' if payment_made is False else 'Not stated — verify'
    voluntary = a.get('voluntary_payment_made')
    voluntary_label = 'Yes' if voluntary is True else 'No' if voluntary is False else 'Not stated — verify'
    unauthorized = a.get('unauthorized_transaction')
    unauthorized_label = 'Yes' if unauthorized is True else 'No' if unauthorized is False else 'Not stated — verify'
    link_clicked = a.get('link_clicked')
    link_label = 'Yes' if link_clicked is True else 'No' if link_clicked is False else 'Not stated — verify'
    attachments = [str(x.get('filename')) for x in evidence if isinstance(x, dict) and x.get('filename')]
    amount_lost_value = a.get('amount_lost')
    if amount_lost_value in (None, '') and a.get('unauthorized_transaction') is False:
        amount_lost_display = '₹0'
    elif amount_lost_value in (None, '') and a.get('voluntary_payment_made') is True:
        amount_lost_display = '₹0 (voluntary transfer; not identified as fraud loss)'
    else:
        amount_lost_display = money(amount_lost_value)

    return f"""VOICE SHIELD AI — CYBER FRAUD COMPLAINT DRAFT

1. COMPLAINANT DETAILS
Complainant name: To be completed by the complainant
Contact details: To be completed by the complainant
Bank/account details: To be completed securely by the complainant
Original transcript language: {transcript_language}
Complaint draft language: {complaint_language}
Incident date/time: {data.get('incident_date') or 'Not provided — verify'}

2. INCIDENT OVERVIEW
Suspected fraud category: {a.get('fraud_category') or data.get('category', 'Other / Unknown')}
Incident status: {a.get('incident_status') or 'UNCLEAR'}
Summary: {a.get('summary') or 'Not provided — verify'}

3. ORIGINAL INCIDENT DESCRIPTION
{transcript or 'Please describe what happened.'}

4. INCIDENT TIMELINE
{chr(10).join(timeline) if timeline else '- Timeline not established — verify with the complainant'}
Note: This sequence is generated from the complainant's description and is not independently verified.

5. FINANCIAL IMPACT
Claimed prize / reward: {money(a.get('claimed_prize_amount'))}
Payment demanded: {money(a.get('payment_requested_amount'))}
Actual fraud loss: {amount_lost_display}
Money sent/debited in incident: {payment_label}
Voluntary payment sent by complainant: {voluntary_label}
Unauthorized transaction/debit reported: {unauthorized_label}
Link clicked: {link_label}
Transaction status: {a.get('transaction_status') or 'Unknown — verify'}
Phone number: {a.get('phone_number') or 'Not provided — verify'}
UPI ID: {a.get('upi_id') or 'Not provided — verify'}
Bank: {a.get('bank_name') or 'Not provided — verify'}

6. CONFIRMED FACTS STATED BY THE COMPLAINANT
{lines(a.get('facts_stated'), 'fact')}

7. POSSIBLE AI INTERPRETATIONS — NOT CONFIRMED FACTS
{bullet(a.get('ai_inferences'))}

8. POTENTIAL SECURITY EXPOSURES — NOT PROOF OF MISUSE
{chr(10).join(exposure_items) if exposure_items else '- No specific exposure identified — verify against the original description'}
Note: A PIN entered inside a payment app to approve a collect request is not automatically evidence that the PIN was disclosed to another person.

9. SUSPICIOUS INDICATORS AND SUPPORTING EVIDENCE
{lines(a.get('indicator_evidence'), 'indicator')}

10. ACTIONS ALREADY TAKEN
To be completed by the complainant. Do not assume any action was taken unless the complainant confirms it.

11. DETAILS STILL TO VERIFY
{bullet(a.get('missing_information'))}

12. EVIDENCE ATTACHMENTS
{chr(10).join('- ' + x for x in attachments) if attachments else '- No evidence files attached to this incident'}

13. COMPLAINANT DECLARATION
I have reviewed this draft and confirm that the information I provide is accurate to the best of my knowledge. I understand that this draft must be checked and submitted independently through the appropriate official channel.

IMPORTANT
This is an editable draft, not a verified finding or legal conclusion. AI interpretations and potential exposures are not confirmed facts. Review every field and quotation. VoiceShield AI does not submit complaints to any government portal.
"""


@app.get('/api/health')
def health(): return jsonify({'ok':True,'service':'VoiceShield AI API','providers':provider_status()})

@app.post('/api/auth/register')
def register():
    body=request.get_json(silent=True) or {}; name=(body.get('name') or '').strip(); email=(body.get('email') or '').strip().lower(); password=body.get('password') or ''
    if len(name)<2 or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$',email) or len(password)<8: return jsonify({'error':'Enter a name, valid email and password with at least 8 characters.'}),400
    try:
        with connect() as db:
            cur=db.execute('INSERT INTO users(name,email,password_hash,preferred_language) VALUES(?,?,?,?)',(name,email,generate_password_hash(password),'English'))
            uid=cur.lastrowid
    except Exception: return jsonify({'error':'An account with this email may already exist.'}),409
    return jsonify({'token':token_for(uid),'user':{'id':uid,'name':name,'email':email,'preferred_language':'English'}}),201

@app.post('/api/auth/login')
def login():
    body=request.get_json(silent=True) or {}; email=(body.get('email') or '').strip().lower(); password=body.get('password') or ''
    with connect() as db: row=db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
    if not row or not check_password_hash(row['password_hash'],password): return jsonify({'error':'Email or password is incorrect.'}),401
    return jsonify({'token':token_for(row['id']),'user':{'id':row['id'],'name':row['name'],'email':row['email'],'preferred_language':row['preferred_language']}})

@app.get('/api/auth/me')
@auth_required
def me(): return jsonify({'user':g.user})

@app.post('/api/auth/logout')
@auth_required
def logout(): return jsonify({'ok':True,'message':'Signed out. Remove the local session token.'})

@app.patch('/api/profile')
@auth_required
def update_profile():
    body=request.get_json(silent=True) or {}; name=(body.get('name') or g.user['name']).strip(); language=body.get('preferred_language','English')
    if language not in LANGUAGES: return jsonify({'error':'Unsupported language.'}),400
    with connect() as db: db.execute('UPDATE users SET name=?,preferred_language=? WHERE id=?',(name,language,g.user['id']))
    return jsonify({'user':{**g.user,'name':name,'preferred_language':language}})

@app.get('/api/providers')
@auth_required
def providers(): return jsonify({'providers':provider_status(),'languages':LANGUAGES,'note':'Provider labels reflect configuration, not language certification.'})

@app.post('/api/voice/transcribe')
@auth_required
def voice_transcribe():
    if 'audio' not in request.files: return jsonify({'error':'Choose an audio file first.'}),400
    f=request.files['audio']; language=request.form.get('language','English')
    if language not in LANGUAGES: return jsonify({'error':'Unsupported language.'}),400
    ext=os.path.splitext(secure_filename(f.filename))[1].lower()
    if ext not in ['.wav','.mp3','.m4a','.ogg','.webm','.mp4','.mpeg']: return jsonify({'error':'Use WAV, MP3, M4A, OGG or WEBM audio.'}),400
    name=f'{uuid.uuid4().hex}{ext}'; path=os.path.join(UPLOAD_DIR,name); f.save(path)
    try: result=transcribe_audio(path,language)
    except GnaniNotConfigured as e: return jsonify({'error':str(e)}),503
    return jsonify(result)

@app.post('/api/fraud/analyze')
@auth_required
def fraud_analyze():
    body=request.get_json(silent=True) or {}; transcript=(body.get('transcript') or '').strip(); language=body.get('language','English')
    if not transcript: return jsonify({'error':'Add or transcribe the incident description first.'}),400
    if language not in LANGUAGES: return jsonify({'error':'Unsupported language.'}),400
    try: result=analyze_text(transcript,language)
    except GnaniNotConfigured as e: return jsonify({'error':str(e)}),503
    status=result.get('incident_status','UNCLEAR'); result['guidance']=GUIDANCE.get(status,GUIDANCE['UNCLEAR'])
    return jsonify(result)

@app.post('/api/voice/speak')
@auth_required
def voice_speak():
    body=request.get_json(silent=True) or {}
    try: return jsonify(synthesize_speech(body.get('text',''),'English'))
    except GnaniNotConfigured as e: return jsonify({'error':str(e)}),503

@app.get('/api/incidents')
@auth_required
def list_incidents():
    with connect() as db: rows=db.execute('SELECT id,title,language,category,status,urgency,summary,created_at,updated_at FROM incidents WHERE user_id=? ORDER BY id DESC',(g.user['id'],)).fetchall()
    return jsonify({'incidents':[dict(r) for r in rows]})

@app.post('/api/incidents')
@auth_required
def create_incident():
    b=request.get_json(silent=True) or {}; transcript=(b.get('transcript') or '').strip(); analysis=b.get('analysis') or {}; status=analysis.get('incident_status','UNCLEAR')
    category=analysis.get('fraud_category','Other / Unknown'); title=(b.get('title') or category).strip()[:100]; language=b.get('language','English')
    if language not in LANGUAGES: return jsonify({'error':'Unsupported language.'}),400
    guidance='\n'.join(GUIDANCE.get(status,GUIDANCE['UNCLEAR']))
    payload={'analysis':analysis,'language':language,'transcript':transcript,'summary':analysis.get('summary','')}
    report=make_report(payload)
    with connect() as db:
        cur=db.execute('INSERT INTO incidents(user_id,title,language,category,status,urgency,summary,transcript,analysis_json,guidance,report_text,source_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
          (g.user['id'],title,language,category,status,'High' if status=='IN_PROGRESS' else ('Review' if status=='UNCLEAR' else 'Action needed'),analysis.get('summary','')[:500],transcript,json.dumps(analysis),guidance,report,b.get('source_type','typed')))
        iid=cur.lastrowid
    return jsonify({'incident':incident_for_id(iid,g.user['id'])}),201

def incident_for_id(iid,uid):
    with connect() as db:
        row=db.execute('SELECT * FROM incidents WHERE id=? AND user_id=?',(iid,uid)).fetchone()
        if not row:return None
        item=dict(row);item['analysis']=json.loads(item.pop('analysis_json') or '{}');item['evidence']=[dict(x) for x in db.execute('SELECT id,filename,mime_type,created_at FROM evidence WHERE incident_id=?',(iid,)).fetchall()]
        return item

@app.get('/api/incidents/<int:iid>')
@auth_required
def get_incident(iid):
    item=incident_for_user(iid)
    return (jsonify({'incident':item}),200) if item else (jsonify({'error':'Incident not found.'}),404)

@app.patch('/api/incidents/<int:iid>')
@auth_required
def patch_incident(iid):
    item=incident_for_user(iid)
    if not item:return jsonify({'error':'Incident not found.'}),404
    b=request.get_json(silent=True) or {}; transcript=b.get('transcript',item['transcript']); title=b.get('title',item['title']); report=b.get('report_text',item['report_text'])
    with connect() as db: db.execute('UPDATE incidents SET title=?,transcript=?,report_text=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?',(title[:100],transcript,report,iid,g.user['id']))
    return jsonify({'incident':incident_for_id(iid,g.user['id'])})

@app.delete('/api/incidents/<int:iid>')
@auth_required
def delete_incident(iid):
    item=incident_for_user(iid)
    if not item:return jsonify({'error':'Incident not found.'}),404
    with connect() as db:
        stored_files = [r['stored_name'] for r in db.execute('SELECT stored_name FROM evidence WHERE incident_id=?', (iid,)).fetchall()]
        db.execute('DELETE FROM incidents WHERE id=? AND user_id=?',(iid,g.user['id']))
    for stored_name in stored_files:
        try: os.remove(os.path.join(UPLOAD_DIR, stored_name))
        except OSError: pass
    return jsonify({'ok':True})

@app.post('/api/incidents/<int:iid>/evidence')
@auth_required
def add_evidence(iid):
    if not incident_for_user(iid):return jsonify({'error':'Incident not found.'}),404
    if 'file' not in request.files:return jsonify({'error':'Choose an image.'}),400
    f=request.files['file']; ext=os.path.splitext(secure_filename(f.filename))[1].lower()
    if ext not in ['.png','.jpg','.jpeg','.webp']:return jsonify({'error':'Only PNG, JPG and WEBP screenshots are accepted.'}),400
    stored=f'{uuid.uuid4().hex}{ext}'; f.save(os.path.join(UPLOAD_DIR,stored))
    with connect() as db: db.execute('INSERT INTO evidence(incident_id,filename,stored_name,mime_type) VALUES(?,?,?,?)',(iid,secure_filename(f.filename),stored,f.mimetype))
    return jsonify({'incident':incident_for_id(iid,g.user['id'])}),201

@app.delete('/api/incidents/<int:iid>/evidence/<int:eid>')
@auth_required
def delete_evidence(iid,eid):
    if not incident_for_user(iid):return jsonify({'error':'Incident not found.'}),404
    with connect() as db:
        row=db.execute('SELECT stored_name FROM evidence WHERE id=? AND incident_id=?',(eid,iid)).fetchone()
        if not row:return jsonify({'error':'Evidence not found.'}),404
        db.execute('DELETE FROM evidence WHERE id=?',(eid,))
    try:os.remove(os.path.join(UPLOAD_DIR,row['stored_name']))
    except OSError:pass
    return jsonify({'ok':True})

def translate_report_to_english(report_text, source_language):
    """Translate a report for PDF export while preserving its facts and structure."""
    if source_language == 'English':
        return report_text

    api_key = os.getenv('GROQ_API_KEY', '').strip()
    if not api_key:
        raise GnaniNotConfigured(
            'English PDF translation needs the configured Groq API. Please check the backend configuration.'
        )

    model = os.getenv('GROQ_MODEL', 'openai/gpt-oss-120b').strip()
    prompt = (
        "Translate the complete cyber-fraud complaint report below into clear, "
        "professional English. The source language is " + source_language + ". "
        "Preserve every heading, section, bullet, date, amount, phone number, "
        "UPI ID, bank name, transaction reference, and factual distinction. "
        "Do not add, infer, omit, summarize, or correct any facts. Translate "
        "the incident description and evidence quotations faithfully into English. "
        "Keep all numeric values and identifiers exactly unchanged. Keep the same "
        "section order and plain-text layout. Output only the translated report, "
        "with no preface or commentary. If any phrase is unclear, mark it "
        "'[unclear in original]' rather than guessing.\n\n"
        "REPORT:\n" + report_text
    )
    try:
        response = requests.post(
            'https://api.groq.com/openai/v1/chat/completions',
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            },
            json={
                'model': model,
                'messages': [
                    {
                        'role': 'system',
                        'content': 'You are a faithful translator. Do not change facts or identifiers.'
                    },
                    {'role': 'user', 'content': prompt}
                ],
                'temperature': 0,
                'max_tokens': 5000
            },
            timeout=(15, 90)
        )
        response.raise_for_status()
        payload = response.json()
        choices = payload.get('choices') or []
        translated = ((choices[0].get('message') or {}).get('content') or '').strip() if choices else ''
        if not translated:
            raise GnaniNotConfigured('Groq returned an empty English translation. Please retry.')
        return translated
    except requests.Timeout as error:
        raise GnaniNotConfigured('English PDF translation timed out. Please try again.') from error
    except requests.RequestException as error:
        raise GnaniNotConfigured('Could not complete English PDF translation. Please try again.') from error
    except (ValueError, IndexError, KeyError, TypeError) as error:
        raise GnaniNotConfigured('Groq returned an unexpected translation response. Please retry.') from error


@app.get('/api/incidents/<int:iid>/report')
@auth_required
def download_report(iid):
    item = incident_for_user(iid)
    if not item:
        return jsonify({'error': 'Incident not found.'}), 404

    report_text = make_report({
        **item,
        'analysis': item.get('analysis', {}),
        'evidence': item.get('evidence', [])
    })

    # Keep the PDF in English. The original transcript remains unchanged in
    # the incident record and is still viewable in the application.
    transcript_text = item.get('transcript') or ''
    source_language = item.get('language') or 'English'
    script_ranges = [
        ('Telugu', r'[\u0C00-\u0C7F]'),
        ('Hindi', r'[\u0900-\u097F]'),
        ('Tamil', r'[\u0B80-\u0BFF]'),
        ('Kannada', r'[\u0C80-\u0CFF]'),
        ('Malayalam', r'[\u0D00-\u0D7F]')
    ]
    detected_scripts = [
        (name, len(re.findall(pattern, transcript_text)))
        for name, pattern in script_ranges
    ]
    detected_scripts.sort(key=lambda entry: entry[1], reverse=True)
    if detected_scripts and detected_scripts[0][1] >= 3:
        source_language = detected_scripts[0][0]

    try:
        report_text = translate_report_to_english(report_text, source_language)
    except GnaniNotConfigured as error:
        return jsonify({'error': str(error)}), 503

    # English-only font: no regional script font registration is required.
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib import colors
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.lib.units import mm

    path = os.path.join(UPLOAD_DIR, f'report-{iid}-{uuid.uuid4().hex[:6]}.pdf')
    doc = SimpleDocTemplate(
        path, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm,
        topMargin=18*mm, bottomMargin=18*mm
    )
    styles = getSampleStyleSheet()
    fonts_dir = os.path.join(os.path.dirname(__file__), 'fonts')
    font_path = os.path.join(fonts_dir, 'DejaVuSans.ttf')
    font_name = 'VoiceShieldEnglish'

    try:
        pdfmetrics.registerFont(TTFont(font_name, font_path))
        body = ParagraphStyle(
            'VSBodyEnglish', parent=styles['BodyText'],
            fontName=font_name, fontSize=9, leading=14, wordWrap='CJK'
        )
        title_style = ParagraphStyle(
            'VSTitleEnglish', parent=styles['Title'],
            fontName=font_name, alignment=TA_CENTER,
            textColor=colors.HexColor('#17365D')
        )
    except Exception:
        body = styles['BodyText']
        title_style = styles['Title']

    story = [
        Paragraph('VoiceShield AI — Cyber Fraud Complaint Draft', title_style),
        Spacer(1, 8)
    ]
    for para in report_text.split('\n'):
        safe = para.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        story.append(Paragraph(safe or '&nbsp;', body))
        story.append(Spacer(1, 4))

    doc.build(story)
    return send_file(
        path, as_attachment=True,
        download_name=f'VoiceShield-Incident-{iid}.pdf',
        mimetype='application/pdf'
    )


@app.errorhandler(413)
def too_large(_): return jsonify({'error':'File is too large. Maximum upload size is configured in the backend .env.'}),413

if __name__=='__main__': app.run(host='127.0.0.1',port=5000,debug=True)
