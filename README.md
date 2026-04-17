# CyberSec Lab

A comprehensive web-based platform for cybersecurity education, assessment, and training. Built with Flask, this platform features real-time SOC monitoring, practical attacking labs (Red Team), defense analysis (Blue Team), and various hands-on vulnerability scenarios.

## Features

- **Red Team Labs**: Hands-on practice with XSS, Command Injection, SQL Injection, and Steganography.
- **Blue Team Dashboard**: Real-time System Monitoring (CPU/RAM/Disk), Attack Logs, and traffic analysis.
- **SOC Integration**: Uses WebSocket (Flask-SocketIO) for real-time alerts (DDoS blocking, traffic logs).
- **AI Phishing Detection**: Integrated machine learning model for detecting malicious/phishing URLs.
- **Threat Intelligence**: IP reputation checks using AbuseIPDB integration.
- **Vulnerability Scanner**: Practical port scanner to analyze target IPs.
- **Identity & Authentication**: Supports digital authentication with TOTP (Time-based One-Time Password) and RBAC.

## Getting Started

### Prerequisites
- Python 3.8+
- Docker and Docker Compose (optional, for containerized run)

### Local Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/CrisDevil222/cyber-sec-lab.git
   cd cyber-sec-lab
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   # Windows
   .\.venv\Scripts\activate
   # Linux/macOS
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Variables:**
   Copy `.env.example` to `.env` and fill in your configurations (Mail, Admin Password, AbuseIPDB Key):
   ```bash
   cp .env.example .env
   ```

5. **Train the ML model (Required for Phishing feature):**
   ```bash
   python train_model.py
   ```

6. **Run the application:**
   ```bash
   python app.py
   ```
   The platform will be available at `http://127.0.0.1:5000`.

### Docker Deployment

To deploy using Docker:
```bash
docker-compose up --build -d
```
The application will start on port 5000.

## Default Credentials
- **Role:** Admin
- **Email:** admin@gmail.com
- **Password:** admin123 (or as configured in `.env`)

---
*Note: This platform is intentionally designed with vulnerable components for educational purposes. Do NOT host it on a public server without strict access control (VPN/Internal network).*
