import os
import time
import socket
import platform
import psutil
import requests
import re
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

from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, abort
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
CTF_TARGET_URL = os.environ.get('TARGET_URL', 'http://35.247.183.253/')

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
        user_input = request.form.get('payload')
        mode = request.form.get('mode')
        if mode == 'unsafe':
            result_unsafe = user_input
            if '<script>' in user_input: log_action('XSS Attack Attempted (Reflected)')
        else:
            result_safe = user_input
    return render_template('xss.html', unsafe=result_unsafe, safe=result_safe)

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


# ==========================================
# 7. KHỞI TẠO DATABASE
# ==========================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
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
    # Chạy bằng SocketIO (thay vì app.run) để hỗ trợ WebSockets cùng với Flask
    socketio.run(app, host='0.0.0.0', port=5000, debug=is_debug, use_reloader=False)