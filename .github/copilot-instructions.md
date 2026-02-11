<!-- Copilot / AI Agent instructions for this repo -->
# Repo-specific guidance for AI coding agents

Purpose
- Short: orient an AI helper to the project's structure, workflows, and important conventions so changes are correct and reproducible.

Quick start (repro)
- Install dependencies: `pip install -r requirements.txt`.
- Additional libs used by some features: `pip install stegano pillow scikit-learn pandas joblib`.
- Train the phishing model before using the AI route: `python train_model.py` → creates `phishing_model.pkl` in repo root.
- Run the site locally: `python app.py` (app binds to port 5000 with `debug=True`).

High-level architecture
- Single Flask app: `app.py` contains routes, DB models, and most business logic; templates live in `templates/` and static assets in `static/`.
- Persistence: SQLAlchemy over SQLite (`database.db` created at startup). On first run the app seeds an admin account and several CTF challenges.
- AI integration: `ai_phishing` route loads a joblib model (`phishing_model.pkl`) and calls `.predict` / `.predict_proba` on raw URL strings.
- Uploads & artifacts: temporary uploads stored in `uploads_temp/`; stego images written to `static/stego_uploads/`.

Project-specific conventions and gotchas
- Tokenizer parity: `custom_tokenizer` is defined in both `train_model.py` and `app.py` — keep them identical. Changing it requires retraining and re-saving the model.
- Model artifact name/path: `phishing_model.pkl` expected at repository root. If you move or rename it, update `app.py` accordingly.
- Training notes: `train_model.py` builds a pipeline with `TfidfVectorizer(tokenizer=custom_tokenizer)` and `LogisticRegression`. Avoid anonymous functions for tokenizer (pickle incompatibility).
- Stego files: prefer PNG inputs to avoid compression artifacts when hiding/revealing messages (`steganography` route enforces `.png` in code).
- Intentional vulnerabilities: many routes (XSS, command injection, SQLi labs) are purposely insecure as teaching exercises. When modifying shared utilities, keep lab behavior intact unless explicitly fixing labs.

Developer workflows & debugging
- No test suite present. To reproduce runtime issues: (1) ensure `phishing_model.pkl` exists, (2) delete `database.db` to re-seed data, (3) run `python app.py` and review console output.
- Debugging tips: the app runs with `debug=True` by default in `app.py`'s main block; use breakpoints or print/log statements when investigating route behavior.

Important files & entry points (examples)
- `app.py` — main application and routes (see `ai_phishing`, `steganography`, `ctf`, `rsa`, etc.).
- `train_model.py` — reproduces `phishing_model.pkl` (training pipeline and tokenizer).
- `requirements.txt` — baseline Python packages; add extras noted above when needed.
- `templates/` — route UIs; examples: `rsa.html`, `stego.html`, `ai_phishing.html`, `ctf.html`.

Editing guidelines for AI agents
- If you change how URLs are vectorized or tokenized, update `train_model.py`, retrain, and commit the new `phishing_model.pkl` (or update `app.py` to load the new artifact name).
- When adding a dependency, update `requirements.txt` to keep local repro consistent.
- When editing routes that are lab content, preserve the intentionally vulnerable behavior unless the issue explicitly requests hardening.

If you find or add CI, tests, or a CONTRIBUTING file, merge their instructions into this doc.

Questions / next steps
- If anything above is unclear, point to the file you want expanded (for example, `app.py` route X). I can iterate.
