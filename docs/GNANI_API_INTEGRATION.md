# Gnani AI integration status

This document distinguishes code that is implemented from provider work that remains incomplete.

## Prisma — speech-to-text
**Status: API integration implemented; requires credentials and live validation in the user's environment.**

`backend/gnani_client.py` contains `transcribe_audio()` and sends audio to the configured `GNANI_PRISMA_URL` using:
- Header: `X-API-Key-ID`
- Multipart file field: `audio_file`
- Form fields: `model=prisma-v3.0`, `language_code`, and `format=transcribe`
- Language codes: `en-IN`, `te-IN`, `hi-IN`, `ta-IN`, `kn-IN`, `ml-IN`

Configure `GNANI_API_KEY` and `GNANI_PRISMA_URL` in `backend/.env` using the current values and instructions from the Gnani console. Confirm the request format and endpoint against the current provider documentation before deployment because provider APIs can change.

## Fraud analysis — Groq
**Status: Implemented separately from Gnani.**

The current text-analysis workflow uses Groq's OpenAI-compatible chat completions API. Configure `GROQ_API_KEY` and `GROQ_MODEL` in `backend/.env`. Do not describe this analysis step as Gnani Evon.

## Evon — reasoning model
**Status: Not integrated.**

The project does not currently call a hosted Evon endpoint or load the Evon model. Any future integration must use the current official model ID, endpoint, authentication, schema and deployment instructions from Gnani/Hugging Face. Validate and constrain model output before using it.

## Timbre — text-to-speech
**Status: Not integrated.**

The current `synthesize_speech()` implementation is a placeholder and returns no generated audio. The frontend control must not be represented as working speech output. Integration requires confirmed beta access, endpoint, authentication, supported voices/languages and audio response handling.

## Validation checklist
Before describing the application as production-ready, test each supported language independently for:
1. Prisma speech-to-text accuracy using staged audio.
2. Transcript editing and fraud analysis.
3. Fraud classification and extracted entities.
4. Correct, reviewed safety guidance.
5. English-only PDF complaint draft readability and factual accuracy.
6. Error handling, privacy and file upload restrictions.

Keep the original transcript available for verification. Do not use real victims' recordings, personal data or credentials in public demos.
