"""Gnani provider adapter.

Prisma: Live Gnani speech-to-text integration.
Groq: Live fraud analysis through the Groq API.
Evon: Not integrated. Timbre: Demo speech generation until connected.
"""

import os
import requests
import re
import json

LANGUAGE_NAMES = [
    'English', 'Telugu', 'Hindi',
    'Tamil', 'Kannada', 'Malayalam'
]


class GnaniNotConfigured(Exception):
    pass


def _demo_enabled():
    return os.getenv('DEMO_MODE', 'true').lower() == 'true'


def transcribe_audio(file_path, language):
    """Transcribe audio using the official Gnani Prisma API."""

    api_key = os.getenv('GNANI_API_KEY')
    endpoint = os.getenv('GNANI_PRISMA_URL')

    if not api_key or not endpoint:
        if _demo_enabled():
            return {
                'text': '[DEMO TRANSCRIPT] Prisma is not configured.',
                'provider': 'Demo mode - not a live Prisma result',
                'is_demo': True
            }

        raise GnaniNotConfigured(
            'Prisma API key or endpoint is missing.'
        )

    language_codes = {
        'English': 'en-IN',
        'Telugu': 'te-IN',
        'Hindi': 'hi-IN',
        'Tamil': 'ta-IN',
        'Kannada': 'kn-IN',
        'Malayalam': 'ml-IN'
    }

    language_code = language_codes.get(language)

    if not language_code:
        raise GnaniNotConfigured('Unsupported Prisma language.')

    try:
        with open(file_path, 'rb') as audio:
            response = requests.post(
                endpoint,
                headers={
                    'X-API-Key-ID': api_key
                },
                files={
                    'audio_file': (
                        os.path.basename(file_path),
                        audio
                    )
                },
                data={
                    'model': 'prisma-v3.0',
                    'language_code': language_code,
                    'format': 'transcribe'
                },
                timeout=90
            )

        response.raise_for_status()
        result = response.json()

        if not result.get('success') or not result.get('transcript'):
            raise GnaniNotConfigured(
                'Prisma returned no transcript. Please try another recording.'
            )

        return {
            'text': result['transcript'],
            'provider': 'Gnani Prisma v3.0',
            'is_demo': False,
            'detected_language': result.get(
                'detected_language_code'
            )
        }

    except requests.RequestException as error:
        raise GnaniNotConfigured(
            f'Prisma request failed: {error}'
        ) from error

    except ValueError as error:
        raise GnaniNotConfigured(
            'Prisma returned an invalid response.'
        ) from error


def _redact_sensitive_values(text):
    """Mask secret values while retaining the incident context for analysis."""
    value = text or ""

    value = re.sub(
        r'(?i)\b(otp|one[- ]time password|upi pin|pin|password)\s*(?:is|:|=)?\s*\d{4,8}\b',
        r'\1 [REDACTED]',
        value
    )

    value = re.sub(
        r'(?<!\d)(?:\d[ -]?){10,18}(?!\d)',
        '[REDACTED ACCOUNT/CARD NUMBER]',
        value
    )

    return value


def _extract_json_object(content):
    """Extract the first valid JSON object, even if the model adds fences or prose."""

    if not isinstance(content, str) or not content.strip():
        raise GnaniNotConfigured(
            "Groq returned an empty analysis."
        )

    cleaned = content.strip().lstrip("\ufeff")

    cleaned = re.sub(
        r"```\s*(?:json)?\s*",
        "",
        cleaned,
        flags=re.I
    )

    cleaned = cleaned.replace("```", "").strip()

    decoder = json.JSONDecoder()

    for match in re.finditer(r"\{", cleaned):
        try:
            data, _ = decoder.raw_decode(
                cleaned[match.start():]
            )
        except json.JSONDecodeError:
            continue

        if isinstance(data, dict):
            return data

    raise GnaniNotConfigured(
        "Groq returned invalid JSON after parsing. Please retry."
    )


def _normalise_quote(value):
    return re.sub(
        r"\s+",
        " ",
        str(value or "")
    ).strip().casefold()


def _verified_evidence_items(items, transcript, label_key):
    """Keep only model claims backed by an exact quote from the source transcript."""

    source = _normalise_quote(transcript)
    verified = []

    if not isinstance(items, list):
        return verified

    for item in items[:20]:
        if not isinstance(item, dict):
            continue

        claim = str(item.get(label_key) or "").strip()[:240]
        quote = str(item.get('evidence_quote') or '').strip()[:500]

        normalized_quote = _normalise_quote(quote)

        if claim and normalized_quote and normalized_quote in source:
            verified.append({
                label_key: claim,
                'evidence_quote': quote
            })

    return verified


def _derive_security_exposures(transcript):
    """Conservative exposure flags; distinguish disclosure from local authorization."""
    sentences = re.split(r'(?<=[.!?।])\s+|\n+', transcript or '')
    patterns = [
        ('Bank account number entered or shared',
         r'\b(?:entered|shared|provided|typed|submitted)\b.{0,70}\b(?:bank )?account number\b|\b(?:bank )?account number\b.{0,70}\b(?:entered|shared|provided|typed|submitted)\b'),
        ('Name entered on a website',
         r'\b(?:entered|typed|submitted)\b.{0,50}\b(?:my )?(?:full )?name\b|\b(?:my )?(?:full )?name\b.{0,50}\b(?:entered|typed|submitted)\b'),
        ('Mobile number entered on a website',
         r'\b(?:entered|typed|submitted)\b.{0,50}\b(?:mobile|phone) number\b|\b(?:mobile|phone) number\b.{0,50}\b(?:entered|typed|submitted)\b'),
        ('OTP shared with another person',
         r'\b(?:shared|told|revealed|provided|read out)\b.{0,50}\b(?:otp|one[- ]time password)\b|\b(?:otp|one[- ]time password)\b.{0,50}\b(?:shared|told|revealed|provided|read out)\b'),
        ('OTP entered on a website',
         r'\b(?:entered|typed|submitted)\b.{0,50}\b(?:otp|one[- ]time password)\b|\b(?:otp|one[- ]time password)\b.{0,50}\b(?:entered|typed|submitted)\b'),
        ('Password shared or entered',
         r'\b(?:shared|revealed|provided|entered|typed|submitted)\b.{0,50}\bpassword\b|\bpassword\b.{0,50}\b(?:shared|revealed|provided|entered|typed|submitted)\b'),
        ('Suspicious link clicked',
         r'\b(?:clicked|opened|visited)\b.{0,50}\b(?:link|url|website)\b|\b(?:link|url|website)\b.{0,50}\b(?:clicked|opened|visited)\b'),
        ('Remote-access app installed',
         r'\b(?:installed|downloaded)\b.{0,50}\b(?:remote access|screen sharing|anydesk|teamviewer)\b'),
    ]
    negative = re.compile(
        r"\b(?:did not|didn't|have not|haven't|never|not)\b.{0,65}\b(?:share|shared|tell|told|reveal|revealed|provide|provided|enter|entered|type|typed|submit|submitted|install|installed|click|clicked|open|opened)\b",
        re.I
    )
    results, seen = [], set()
    for sentence in sentences:
        clean = sentence.strip()
        if not clean or negative.search(clean):
            continue
        # Entering a UPI PIN locally to approve a collect request is not proof
        # that the PIN was disclosed to the caller or compromised.
        if re.search(r'\bupi\s+pin\b', clean, re.I):
            if re.search(r'\b(?:entered|typed)\b.{0,45}\bupi\s+pin\b', clean, re.I) and re.search(
                r'\b(?:approve|approved|authori[sz]e|authori[sz]ed|collect request)\b', clean, re.I
            ):
                continue
            if re.search(r'\b(?:shared|revealed|provided|told|read out)\b.{0,45}\bupi\s+pin\b|\bupi\s+pin\b.{0,45}\b(?:shared|revealed|provided|told|read out)\b', clean, re.I):
                key = 'UPI PIN disclosed to another person'
                if key not in seen:
                    results.append({'exposure': key, 'evidence_quote': clean[:500]}); seen.add(key)
        for label, pattern in patterns:
            if label in seen or not re.search(pattern, clean, re.I):
                continue
            results.append({'exposure': label, 'evidence_quote': clean[:500]})
            seen.add(label)
    return results


def analyze_text(transcript, language):
    """Analyze a cyber-fraud incident with the Groq API."""

    api_key = os.getenv('GROQ_API_KEY', '').strip()

    if not api_key:
        if _demo_enabled():
            text = (transcript or '').lower()

            if any(x in text for x in [
                'digital arrest', 'under arrest',
                'police officer', 'cbi', 'customs officer'
            ]):
                category = 'Digital Arrest Scam'

            elif any(x in text for x in [
                'kyc', 'know your customer',
                'account will be blocked',
                'bank officer', 'bank representative'
            ]):
                category = 'Banking Impersonation / Fake KYC'

            elif any(x in text for x in [
                'otp', 'one-time password',
                'password', 'upi pin', 'credential'
            ]):
                category = 'OTP / Credential Theft'

            elif any(x in text for x in [
                'phishing', 'suspicious link',
                'fake website', 'click this link'
            ]):
                category = 'Phishing'

            elif any(x in text for x in [
                'qr code', 'collect request',
                'upi', 'payment link', 'payment request'
            ]):
                category = 'UPI / Payment Fraud'

            elif any(x in text for x in [
                'customer care', 'customer support', 'impersonat'
            ]):
                category = 'Impersonation Scam'

            else:
                category = 'Other / Unknown'

            ongoing = any(x in text for x in [
                'right now', 'currently',
                'asking me to pay', 'transfer now',
                'still on the call', 'right away'
            ])

            happened = any(x in text for x in [
                'deducted', 'debited', 'money was taken',
                'transferred', 'lost money',
                'sent money', 'shared the otp', 'shared it'
            ])

            status = (
                'IN_PROGRESS' if ongoing
                else 'ALREADY_HAPPENED' if happened
                else 'SUSPICIOUS_ATTEMPT'
            )

            amount_match = re.search(
                r'(?:₹|rs\.?\s*)\s?([\d,]+)',
                transcript or '',
                re.I
            )

            return {
                'fraud_category': category,
                'incident_status': status,
                'amount': amount_match.group(1).replace(',', '') if amount_match else None,
                'phone_number': None,
                'upi_id': None,
                'bank_name': None,
                'transaction_status': 'Unknown - verify',
                'summary': (transcript or 'No transcript provided')[:280],
                'facts_stated': [],
                'ai_inferences': [],
                'security_exposures': [],
                'indicator_evidence': [],
                'missing_information': [
                    'Bank name',
                    'Exact incident date/time',
                    'Transaction reference'
                ],
                'requires_user_verification': True,
                'provider': 'Demo rules - not a live AI result',
                'is_demo': True
            }

        raise GnaniNotConfigured(
            'Groq API key is missing. Add GROQ_API_KEY to backend/.env.'
        )

    safe_transcript = _redact_sensitive_values(transcript)

    system_prompt = """You are the incident-analysis engine for VoiceShield AI, an Indian cyber-fraud victim assistance application.

Analyze the supplied incident transcript. It may contain Telugu, Hindi, Tamil, Kannada, Malayalam, English, or code-mixed speech. Understand it in its original language; do not translate or rewrite the transcript.

Do not invent facts. Use null when a field is not explicitly supported. Do not treat a suspected event as confirmed fraud without evidence. Distinguish an ongoing attempt from a completed loss.

Return ONLY one valid JSON object with these exact keys:
{
  "fraud_category": "UPI / Payment Fraud | Banking Impersonation / Fake KYC | Phishing | Digital Arrest Scam | Impersonation Scam | OTP / Credential Theft | Lottery / Advance-Fee Scam | Other / Unknown",
  "incident_status": "IN_PROGRESS | ALREADY_HAPPENED | SUSPICIOUS_ATTEMPT | UNCLEAR",
  "amount": "legacy display amount; payment requested if present, otherwise actual loss, otherwise claimed prize; numeric string or null",
  "claimed_prize_amount": "prize or reward amount promised, numeric string or null",
  "payment_requested_amount": "amount sender demanded the victim pay, numeric string or null",
  "amount_lost": "amount explicitly paid or lost by the victim, numeric string or null",
  "payment_made": "legacy field: true only if victim confirms money was sent/debited as part of this incident; false if explicitly no payment/debit; otherwise null",
  "voluntary_payment_made": "true if victim intentionally sent money; false if no voluntary transfer; otherwise null",
  "unauthorized_transaction": "true if victim reports an unauthorized debit/transaction; false if explicitly no debit/transaction; otherwise null",
  "link_clicked": "true, false, or null if not stated",
  "phone_number": "phone number explicitly stated or null",
  "upi_id": "UPI ID explicitly stated or null",
  "bank_name": "bank name explicitly stated or null",
  "transaction_status": "short factual status, or Unknown - verify",
  "summary": "concise factual summary, maximum 3 sentences",
  "facts_stated": [{"fact": "short factual statement", "evidence_quote": "exact verbatim substring from transcript"}],
  "ai_inferences": ["carefully qualified interpretation, not a confirmed fact"],
  "security_exposures": [{"exposure": "possible exposure", "evidence_quote": "exact verbatim substring from transcript"}],
  "indicator_evidence": [{"indicator": "suspicious indicator", "evidence_quote": "exact verbatim substring from transcript"}],
  "suspicious_indicators": ["specific indicators supported by transcript"],
  "missing_information": ["useful details the user should provide"],
  "requires_user_verification": true
}

Rules:
- Never confuse a claimed prize with a payment demand or actual financial loss.
- A request to pay a fee to release a prize is a Lottery / Advance-Fee Scam, not automatically phishing or impersonation.
- Set amount_lost to null unless payment/loss is explicitly confirmed. If the user explicitly says no payment was made, amount_lost may be "0".
- Set payment_made, voluntary_payment_made, unauthorized_transaction and link_clicked to null if unstated. A link being present does not mean it was clicked.
- If a UPI collect request is approved and money is debited, set payment_made=true and unauthorized_transaction=true when the victim says they intended to receive money, not send it. Set voluntary_payment_made=false. Do not describe this as the victim voluntarily paying the scammer.
- If OTP is shared and a debit follows, report the debit as a transaction/loss; do not automatically say the victim voluntarily paid.
- If the victim explicitly says no money was deducted, set amount_lost="0", unauthorized_transaction=false and payment_made=false.
- A normal, intentional transfer to a friend or known recipient is not a fraud loss. Set voluntary_payment_made=true, payment_made=true, unauthorized_transaction=false, amount_lost="0", and incident_status="UNCLEAR" unless a separate suspicious event is described.
- A completed ordinary transaction does NOT mean incident_status="IN_PROGRESS". Use IN_PROGRESS only when a suspicious interaction or attack is actively underway. Use UNCLEAR for ordinary activity with no fraud indicators.
- Do not classify ordinary bank KYC updates performed inside the official banking app as fake KYC without concrete malicious indicators.
- Do not label an ordinary transfer as a payment demand merely because an amount or transfer is mentioned.
- Never infer exposure of Aadhaar, card details, OTP, UPI PIN, or password from a scammer's request or claim. Record only what the victim actually entered/shared, with exact evidence.
- Every evidence_quote MUST be copied exactly from the original transcript, without paraphrasing.
- Never create a fact, exposure or suspicious indicator without an exact supporting quote.
- Put interpretations only in ai_inferences and label them as possible, not confirmed.
- Do not say a password/OTP/PIN was requested or shared unless the transcript explicitly supports it.
- Do not provide emergency or legal instructions; the application supplies safety guidance separately.
- Always set requires_user_verification to true.
Return JSON only."""

    user_prompt = (
        f"Incident language selected by the user: {language}\\n"
        f"Transcript (sensitive numeric secrets have been masked):\\n{safe_transcript}"
    )

    model = os.getenv('GROQ_MODEL', 'openai/gpt-oss-120b').strip()
    api_key = os.getenv('GROQ_API_KEY', '').strip()
    if not api_key:
        raise GnaniNotConfigured(
            'Groq API key is missing. Add GROQ_API_KEY to backend/.env.'
        )

    endpoint = 'https://api.groq.com/openai/v1/chat/completions'
    request_body = {
        'model': model,
        'messages': [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_prompt}
        ],
        'temperature': 0,
        'max_tokens': 3000,
        'response_format': {'type': 'json_object'}
    }

    try:
        response = requests.post(
            endpoint,
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            },
            json=request_body,
            timeout=(15, 90)
        )
        if response.status_code >= 400:
            detail = ''
            try:
                error_obj = response.json().get('error') or {}
                detail = error_obj.get('message', '') if isinstance(error_obj, dict) else str(error_obj)
            except (ValueError, AttributeError):
                detail = response.text[:300]
            raise GnaniNotConfigured(
                f'Groq API error ({response.status_code}). '
                f'{detail or "Check the API key, model access and rate limits."}'
            )

        payload = response.json()
        choices = payload.get('choices') or []
        if not choices:
            raise GnaniNotConfigured('Groq returned no analysis response. Please retry.')

        content = ((choices[0].get('message') or {}).get('content') or '')
        result = _extract_json_object(content)

    except requests.Timeout as error:
        raise GnaniNotConfigured('Groq analysis timed out. Please try again.') from error
    except requests.RequestException as error:
        raise GnaniNotConfigured(f'Could not reach Groq: {error}') from error
    except (ValueError, IndexError, KeyError, TypeError) as error:
        raise GnaniNotConfigured('Groq returned an unexpected response. Please retry.') from error

    allowed_categories = {
        'UPI / Payment Fraud',
        'Banking Impersonation / Fake KYC',
        'Phishing',
        'Digital Arrest Scam',
        'Impersonation Scam',
        'OTP / Credential Theft',
        'Lottery / Advance-Fee Scam',
        'Other / Unknown'
    }

    allowed_statuses = {
        'IN_PROGRESS',
        'ALREADY_HAPPENED',
        'SUSPICIOUS_ATTEMPT',
        'UNCLEAR'
    }

    raw_category = str(
        result.get('fraud_category') or ''
    ).strip().lower()

    category_aliases = {
        'advance fee fraud / lottery scam': 'Lottery / Advance-Fee Scam',
        'advance-fee fraud': 'Lottery / Advance-Fee Scam',
        'lottery scam': 'Lottery / Advance-Fee Scam',
        'prize scam': 'Lottery / Advance-Fee Scam',
        'advance fee scam': 'Lottery / Advance-Fee Scam',
    }

    normalized_category = category_aliases.get(raw_category)

    if normalized_category:
        result['fraud_category'] = normalized_category

    elif result.get('fraud_category') not in allowed_categories:
        result['fraud_category'] = 'Other / Unknown'

    if result.get('incident_status') not in allowed_statuses:
        result['incident_status'] = 'UNCLEAR'

    source_text = (transcript or '').lower()

    # Conservative false-positive guard for a routine KYC update completed
    # inside the bank's official app, with explicit negative fraud facts.
    official_app_kyc = (
        re.search(r'\bofficial\b.{0,45}\b(?:banking|bank)\b.{0,30}\bapp\b|\b(?:banking|bank)\b.{0,30}\bofficial\b.{0,30}\bapp\b', source_text)
        and re.search(r'\bkyc\b', source_text)
        and re.search(r'\b(?:did not|didn.t|never)\b.{0,55}\b(?:click|open)\b', source_text)
        and re.search(r'\b(?:no money was deducted|no money deducted|no unusual payments|did not share.*otp|didn.t share.*otp)\b', source_text)
        and not re.search(r'\b(?:fake|phishing|impersonat|unauthori[sz]ed debit|money deducted|otp shared|password shared)\b', source_text)
    )
    if official_app_kyc:
        result['fraud_category'] = 'Other / Unknown'
        result['incident_status'] = 'UNCLEAR'
        result['suspicious_indicators'] = []
        result['indicator_evidence'] = []
        result['ai_inferences'] = [
            'The description is consistent with a routine KYC update completed inside the bank’s official app. No clear fraud indicator is established by the stated facts.'
        ]
        result['summary'] = 'The complainant reports completing a KYC update through the bank’s official app and reports no suspicious call, OTP disclosure, unusual payment, or financial deduction. No clear fraud attempt is established from the description.'

    prize_pattern = r'\b(win|won|winner|prize|lottery|lucky draw|reward)\b'

    fee_pattern = (
        r'\b(processing fee|claim fee|release fee|registration fee|pay|payment|transfer)\b'
    )

    if (
        re.search(prize_pattern, source_text)
        and re.search(fee_pattern, source_text)
    ):
        result['fraud_category'] = 'Lottery / Advance-Fee Scam'

    scalar_fields = [
        'amount',
        'claimed_prize_amount',
        'payment_requested_amount',
        'amount_lost',
        'phone_number',
        'upi_id',
        'bank_name'
    ]

    for field in scalar_fields:
        value = result.get(field)

        if value is not None and not isinstance(value, (str, int, float)):
            result[field] = None

        elif value is not None:
            result[field] = str(value)[:100]

    for field in ['payment_made', 'voluntary_payment_made', 'unauthorized_transaction', 'link_clicked']:
        value = result.get(field)

        if isinstance(value, str):
            lowered = value.strip().lower()

            if lowered in ('true', 'yes'):
                result[field] = True

            elif lowered in ('false', 'no'):
                result[field] = False

            else:
                result[field] = None

        elif not isinstance(value, bool):
            result[field] = None

    result['facts_stated'] = _verified_evidence_items(
        result.get('facts_stated'),
        transcript,
        'fact'
    )

    result['indicator_evidence'] = _verified_evidence_items(
        result.get('indicator_evidence'),
        transcript,
        'indicator'
    )

    result['security_exposures'] = _verified_evidence_items(
        result.get('security_exposures'),
        transcript,
        'exposure'
    )

    inferences = result.get('ai_inferences')

    result['ai_inferences'] = (
        [
            str(x)[:240]
            for x in inferences[:10]
            if isinstance(x, (str, int, float))
        ]
        if isinstance(inferences, list)
        else []
    )

    derived_exposures = _derive_security_exposures(transcript)

    if derived_exposures:
        result['security_exposures'] = derived_exposures

    source_lower = (transcript or '').lower()

    explicit_no_payment = bool(re.search(
        r"\b(?:i (?:did not|didn't|have not|haven't) (?:make|send|pay|transfer)|no payment (?:was )?made|i refused to (?:pay|make the payment)|i have not transferred any money)\b",
        source_lower
    ))

    if result.get('payment_made') is False and explicit_no_payment:
        result['amount_lost'] = '0'

        if (
            not result.get('transaction_status')
            or result.get('transaction_status') == 'Unknown - verify'
        ):
            result['transaction_status'] = (
                'No payment made — user stated they did not pay'
            )

    result['amount'] = (
        result.get('payment_requested_amount')
        or result.get('amount_lost')
        or result.get('claimed_prize_amount')
        or result.get('amount')
    )

    for field in ['summary', 'transaction_status']:
        value = result.get(field)

        result[field] = (
            str(value)[:600]
            if value
            else 'Not provided — verify'
        )

    missing = result.get('missing_information')

    result['missing_information'] = (
        [str(item)[:120] for item in missing[:12]]
        if isinstance(missing, list)
        else []
    )

    indicators = result.get('suspicious_indicators')

    proposed = (
        [str(item)[:180] for item in indicators[:10]]
        if isinstance(indicators, list)
        else []
    )

    verified_labels = {
        x['indicator']
        for x in result['indicator_evidence']
    }

    verified_labels.update(
        x['exposure']
        for x in result['security_exposures']
    )

    result['suspicious_indicators'] = [
        x for x in proposed
        if x in verified_labels
    ]

    if not result['suspicious_indicators']:
        result['suspicious_indicators'] = [
            x['indicator']
            for x in result['indicator_evidence']
        ]

    result['requires_user_verification'] = True
    result['provider'] = f'Groq {model}'
    result['is_demo'] = False

    return result


def synthesize_speech(text, language):
    """Demo speech generation until Timbre is connected."""

    if _demo_enabled():
        return {
            'audio_url': None,
            'provider': 'Demo mode - no audio generated',
            'is_demo': True
        }

    raise GnaniNotConfigured(
        'Timbre is not configured. Official API integration is pending.'
    )


def provider_status():
    """Report live configuration separately for each provider."""

    gnani_key = bool(os.getenv('GNANI_API_KEY'))
    prisma_configured = gnani_key and bool(os.getenv('GNANI_PRISMA_URL'))
    groq_configured = bool(os.getenv('GROQ_API_KEY', '').strip())
    timbre_configured = gnani_key and bool(os.getenv('GNANI_TIMBRE_URL'))

    return {
        'mode': 'live' if (prisma_configured or groq_configured) else 'demo',
        'prisma': 'Configured' if prisma_configured else 'Demo mode',
        'evon': 'Not integrated',
        'timbre': 'Configured - integration pending' if timbre_configured else 'Demo mode',
        'analysis_provider': (
            f'Groq {os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")}'
            if groq_configured else 'Demo rules'
        ),
        'analysis_is_demo': not groq_configured
    }
