# VoiceShield AI

**Speak. Detect. Protect. Report.**

VoiceShield AI is a multilingual cyber-fraud assistance prototype that helps a person describe a suspected scam, inspect an AI-assisted analysis, review practical safety steps, and prepare an editable complaint draft.

## What it does
- Six-language interface/workflow: English, Telugu, Hindi, Tamil, Kannada and Malayalam.
- Audio recording/upload and speech-to-text through the **Gnani Prisma v3.0** integration.
- Current LLM-based fraud analysis through **Groq** (OpenAI-compatible API).
- Fraud category and incident-status assessment, financial details, evidence quotations and verification flags.
- Rule-based safety guidance for common cyber-fraud scenarios in India.
- User accounts, incident history, editable complaint drafts and PDF export.
- Evidence image upload and management.
- Local SQLite persistence.

## AI provider status — please read
- **Gnani Prisma v3.0:** speech-to-text API integration is implemented. It requires the user's own Gnani API key and Prisma endpoint in `backend/.env`.
- **Groq:** used for the current fraud-analysis workflow. It requires a Groq API key and model setting in `backend/.env`.
- **Gnani Evon:** not integrated in this version.
- **Gnani Timbre:** not integrated in this version; the speech-generation UI is a placeholder. Do not present it as a working live feature.

The app supports a six-language workflow, but this does not certify every language/provider combination as production-ready. Validate speech recognition, analysis, safety guidance and report output independently for each language.

## Requirements
- Python 3.10+
- Node.js 18+
- npm

## Run on Windows

### 1. Configure backend
From the project root in PowerShell:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `backend/.env` locally:
- Set a long random `FLASK_SECRET_KEY`.
- Set `GROQ_API_KEY` and `GROQ_MODEL` for fraud analysis.
- Set `GNANI_API_KEY` and `GNANI_PRISMA_URL` using the values from your Gnani console.

Never commit `.env` or share credentials publicly. If running without live credentials, set `DEMO_MODE=true` for clearly labelled demo behavior where supported. Use `DEMO_MODE=false` only when the providers you intend to use are configured.

Start the backend:
```powershell
python app.py
```
Backend: `http://127.0.0.1:5000`.

### 2. Configure and start frontend
Open a second PowerShell window from the project root:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite (usually `http://localhost:5173`).

Alternatively, from the project root on Windows, use `start_backend_windows.bat` and `start_frontend_windows.bat` after configuring `backend/.env`.

## Project documents
- [One-page project pitch](docs/VoiceShield_Project_Pitch.pdf)
- [Feature and workflow checklist](docs/FEATURE_CHECKLIST.md)
- [Gnani API integration notes](docs/GNANI_API_INTEGRATION.md)
- [Windows installation guide](INSTALL.txt)

## Project structure
```text
VoiceShield_AI/
  backend/
    app.py
    database.py
    gnani_client.py
    requirements.txt
    .env.example
    fonts/
  frontend/
    src/
    package.json
    package-lock.json
    .env.example
  docs/
    VoiceShield_Project_Pitch.pdf
    FEATURE_CHECKLIST.md
    GNANI_API_INTEGRATION.md
  INSTALL.txt
  start_backend_windows.bat
  start_frontend_windows.bat
```

## Privacy, safety and limitations
- Use fictional data and staged recordings for demonstrations.
- Local incident records are stored in `backend/voiceshield.db`; uploaded audio and evidence are stored under `backend/uploads/`. These runtime files are intentionally excluded from this GitHub source package.
- Never commit API keys, `.env`, real incident transcripts, recordings, screenshots, database files or generated reports.
- This is an assistance prototype, not a bank, police service or official reporting portal. It does not submit complaints or contact banks/police.
- AI output is not a verified finding. Review all facts and quotations before using a complaint draft.
- Do not use real passwords, OTPs, UPI PINs or banking credentials in testing.
- Authentication and local file storage are prototype-grade. Add HTTPS, secure session controls, access controls, encryption, retention policies, rate limiting, backups and an independent security review before public deployment.

## License
No open-source license is included. Add a license only if you intend to publish the project under a specific open-source license.
