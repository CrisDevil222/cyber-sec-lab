import os 
import base64
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
import joblib 
import requests
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

# --- QUAN TRỌNG: Phải định nghĩa hàm này y hệt như bên file train ---
def custom_tokenizer(url):
    return str(url).split('.')
# -------------------------------------------------------------------
# Thư viện Steganography
try:
    from stegano import lsb
    from PIL import Image
except ImportError:
    print("Thiếu thư viện! Hãy chạy: pip install stegano pillow")

# --- KIỂM TRA PYOTP ---
try:
    import pyotp
except ImportError:
    print("Thiếu thư viện! Hãy chạy: pip install pyotp")
    exit()

# --- CẤU HÌNH APP ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'ultimate-cyber-lab-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads_temp'
app.config['STEGO_FOLDER'] = 'static/stego_uploads' # Thư mục lưu ảnh Stego
# API Key của AbuseIPDB (Thay bằng key thật của bạn)
ABUSEIPDB_KEY = "8ff0ad59beabe87ac7299daa193cdc2b40a358a241dc94434a3bfe52d1b0b49d76986283e541422a"
# Tạo các thư mục cần thiết
for folder in [app.config['UPLOAD_FOLDER'], app.config['STEGO_FOLDER']]:
    if not os.path.exists(folder):
        os.makedirs(folder)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), default='user')
    totp_secret = db.Column(db.String(32), nullable=True)
    score = db.Column(db.Integer, default=0) # Điểm CTF
    solved_challenges = db.Column(db.String(500), default="") # Lưu ID các bài đã giải

from datetime import datetime

# --- BẢNG LƯU TRỮ ĐÓNG GÓP Ý KIẾN ---
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# --- ROUTE XỬ LÝ FORM GÓP Ý ---
@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    name = request.form.get('name')
    content = request.form.get('content')
    
    if name and content:
        new_fb = Feedback(name=name, content=content)
        db.session.add(new_fb)
        db.session.commit()
        # Hiện thông báo cảm ơn
        flash('Cảm ơn bạn đã đóng góp ý kiến! Quản trị viên sẽ xem xét.', 'success')
        
    # Quay lại trang trước đó
    return redirect(request.referrer or url_for('index'))

    # ... (Phần trên của hàm submit_feedback) ...
    if name and content:
        new_fb = Feedback(name=name, content=content)
        db.session.add(new_fb)
        db.session.commit()
        # Hiện thông báo cảm ơn
        flash('Cảm ơn bạn đã đóng góp ý kiến! Quản trị viên sẽ xem xét.', 'success')
        
    # Quay lại trang trước đó
    return redirect(request.referrer or url_for('index'))

# ==========================================================
# 👇 BẠN DÁN ĐOẠN CODE ADMIN VÀO NGAY KHOẢNG TRỐNG NÀY 👇
# ==========================================================

# --- TRANG ADMIN XEM GÓP Ý ---
@app.route('/admin/feedbacks')
# Bạn có thể thêm @login_required vào đây nếu muốn bảo mật
def view_feedbacks():
    # Lấy toàn bộ ý kiến từ mới nhất đến cũ nhất
    all_feedbacks = Feedback.query.order_by(Feedback.timestamp.desc()).all()
    
    # Render giao diện HTML đơn giản ngay trong Python để khỏi cần tạo file mới
    html = "<h2>Danh sách ý kiến đóng góp:</h2><ul>"
    for fb in all_feedbacks:
        time_str = fb.timestamp.strftime('%Y-%m-%d %H:%M')
        html += f"<li style='margin-bottom:15px'><b>{fb.name}</b> <i>({time_str})</i>: <br>{fb.content}</li>"
    html += "</ul><a href='/'>Quay lại trang chủ</a>"
    return html

# ==========================================================
# (Và bên dưới này tiếp tục là các route cũ của bạn...)
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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_action(action):
    if current_user.is_authenticated:
        try:
            new_log = AuditLog(user_id=current_user.id, action=action)
            db.session.add(new_log)
            db.session.commit()
        except:
            db.session.rollback()

# --- AUTH ROUTES ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            log_action('Logged in')
            return redirect(url_for('dashboard'))
        flash('Sai thông tin đăng nhập.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username đã tồn tại.', 'warning')
            return redirect(url_for('register'))
        
        totp_secret = pyotp.random_base32()
        new_user = User(username=username, password=generate_password_hash(password), role='user', totp_secret=totp_secret)
        db.session.add(new_user)
        db.session.commit()
        flash('Đăng ký thành công.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- MAIN ROUTES ---
@app.route('/')
def index(): return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard(): return render_template('dashboard.html', name=current_user.username)

# API cho Chart.js
@app.route('/api/stats')
@login_required
def api_stats():
    # Thống kê cho biểu đồ
    log_counts = {
        'Login': AuditLog.query.filter(AuditLog.action == 'Logged in').count(),
        'Attacks': AuditLog.query.filter(AuditLog.action.contains('Attack')).count(),
        'Tools': AuditLog.query.filter(~AuditLog.action.in_(['Logged in']) & ~AuditLog.action.contains('Attack')).count()
    }
    
    # Top người dùng tích cực (Top solves)
    top_users = User.query.order_by(User.score.desc()).limit(5).all()
    leaderboard = [{'username': u.username, 'score': u.score} for u in top_users]
    
    return jsonify({'logs': log_counts, 'leaderboard': leaderboard})

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin': return redirect(url_for('dashboard'))
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return render_template('admin.html', logs=logs)

# --- NEW MODULES ---

# 1. XSS LAB (Cross-Site Scripting)
@app.route('/xss', methods=['GET', 'POST'])
@login_required
def xss_lab():
    result_unsafe = ""
    result_safe = ""
    if request.method == 'POST':
        user_input = request.form.get('payload')
        mode = request.form.get('mode')
        
        if mode == 'unsafe':
            # Không lọc gì cả -> XSS chạy
            result_unsafe = user_input
            if '<script>' in user_input:
                log_action('XSS Attack Attempted (Reflected)')
        else:
            # Flask tự động escape HTML -> An toàn
            result_safe = user_input
            
    return render_template('xss.html', unsafe=result_unsafe, safe=result_safe)

# 2. COMMAND INJECTION (RCE)
@app.route('/cmd_injection', methods=['GET', 'POST'])
@login_required
def cmd_injection():
    output = ""
    if request.method == 'POST':
        target_ip = request.form.get('ip')
        # Lỗ hổng: Nối chuỗi trực tiếp
        # Windows dùng 'ping -n 1', Linux dùng 'ping -c 1'
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = f"ping {param} 1 {target_ip}" 
        
        try:
            # Nguy hiểm: shell=True
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=5)
            output = output.decode('utf-8', errors='ignore') # Decode byte sang string
            
            # Kiểm tra xem user có lén chạy lệnh khác không (vd: & dir)
            if '&' in target_ip or '|' in target_ip or ';' in target_ip:
                log_action('Command Injection RCE Detected!')
        except subprocess.CalledProcessError as e:
            output = f"Error: {e.output.decode('utf-8')}"
        except Exception as e:
            output = str(e)
            
    return render_template('cmd_injection.html', output=output)

# 3. STEGANOGRAPHY (Giấu tin trong ảnh)
# --- MODULE STEGANOGRAPHY (Đã sửa lỗi Tiếng Việt) ---
@app.route('/steganography', methods=['GET', 'POST'])
@login_required
def steganography():
    hidden_img_url = None
    revealed_message = None
    error = None

    if request.method == 'POST':
        action = request.form.get('action')
        
        # --- XỬ LÝ GIẤU TIN (ENCODE) ---
        if action == 'encode':
            if 'image' not in request.files:
                error = 'Chưa chọn ảnh!'
            else:
                file = request.files['image']
                message = request.form.get('message', '')

                if file.filename == '':
                    error = 'Chưa chọn file ảnh!'
                elif not message:
                    error = 'Chưa nhập tin nhắn bí mật!'
                else:
                    # Lưu ảnh gốc tạm thời
                    filename = secure_filename(file.filename)
                    input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(input_path)

                    # Tên file đầu ra
                    output_filename = f"secret_{filename.split('.')[0]}.png"
                    output_path = os.path.join(app.config['STEGO_FOLDER'], output_filename)

                    try:
                        # --- QUAN TRỌNG: Mã hóa Tiếng Việt sang Base64 trước khi giấu ---
                        # 1. Chuyển chuỗi Tiếng Việt sang bytes (utf-8)
                        # 2. Mã hóa bytes đó sang Base64
                        # 3. Chuyển lại thành chuỗi ASCII để thư viện Stegano đọc được
                        encoded_message = base64.b64encode(message.encode('utf-8')).decode('utf-8')
                        
                        # Giấu chuỗi Base64 vào ảnh
                        secret = lsb.hide(input_path, encoded_message)
                        secret.save(output_path)
                        
                        # Tạo URL để hiển thị/tải về
                        hidden_img_url = url_for('static', filename=f'stego_uploads/{output_filename}')
                    except Exception as e:
                        error = f"Lỗi khi giấu tin: {str(e)}"

        # --- XỬ LÝ GIẢI MÃ (DECODE) ---
        elif action == 'decode':
            if 'stego_image' not in request.files:
                error = 'Chưa chọn ảnh cần giải mã!'
            else:
                file = request.files['stego_image']
                if file.filename == '':
                    error = 'Chưa chọn file!'
                else:
                    # Lưu tạm ảnh upload lên để đọc
                    filename = secure_filename(file.filename)
                    input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(input_path)

                    try:
                        # Lấy nội dung thô từ ảnh
                        raw_message = lsb.reveal(input_path)
                        
                        if raw_message:
                            try:
                                # --- QUAN TRỌNG: Giải mã Base64 về lại Tiếng Việt ---
                                revealed_message = base64.b64decode(raw_message).decode('utf-8')
                            except:
                                # Nếu giải mã Base64 lỗi (do ảnh cũ không dùng Base64), thì hiển thị nguyên gốc
                                revealed_message = raw_message
                        else:
                            error = "Không tìm thấy tin nhắn nào trong ảnh này!"
                    except Exception as e:
                         error = f"Lỗi khi đọc ảnh: {str(e)}"

    return render_template('steganography.html', 
                           hidden_img_url=hidden_img_url, 
                           revealed_message=revealed_message,
                           error=error)

# 4. GAMIFICATION (CTF Challenges)
@app.route('/ctf', methods=['GET', 'POST'])
@login_required
def ctf():
    challenges = Challenge.query.all()
    solved_list = current_user.solved_challenges.split(',')
    
    if request.method == 'POST':
        chal_id = request.form.get('chal_id')
        flag_submit = request.form.get('flag').strip()
        
        chal = Challenge.query.get(int(chal_id))
        
        if str(chal.id) in solved_list:
            flash('Bạn đã giải bài này rồi!', 'info')
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

# --- OLD MODULES (Giữ nguyên) ---
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
        # Simple Luhn
        digits = [int(d) for d in str(cc) if d.isdigit()]
        checksum = sum(digits[-1::-2]) + sum([sum(divmod(d*2,10)) for d in digits[-2::-2]])
        valid = (checksum % 10 == 0) and (len(digits)>12)
        key = Fernet.generate_key()
        res = {'is_valid': valid, 'enc': Fernet(key).encrypt(f"{cc}".encode()).decode()}
    return render_template('ecommerce.html', result=res)

@app.route('/vulnerability', methods=['GET', 'POST'])
@login_required
def vulnerability():
    res, tgt = [], ""
    if request.method == 'POST':
        tgt = request.form.get('target_ip')
        try:
            ip = socket.gethostbyname(tgt)
            for p in [80, 443, 3306]:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.5)
                res.append({'port':p,'status':"OPEN" if s.connect_ex((ip,p))==0 else "CLOSED"})
                s.close()
        except: pass
    return render_template('vulnerability.html', results=res, target=tgt)

@app.route('/malware', methods=['GET', 'POST'])
@login_required
def malware():
    anl = None
    if request.method == 'POST':
        f = request.files.get('malware_sample')
        if f:
            b = f.read()
            anl = {'name': f.filename, 'md5': hashlib.md5(b).hexdigest(), 'sha256': hashlib.sha256(b).hexdigest()}
    return render_template('malware.html', analysis=anl)

@app.route('/system_security')
@login_required
def system_security():
    info = {'os': platform.system(), 'cpu': psutil.cpu_count(), 'ram': f"{round(psutil.virtual_memory().total/1024**3,1)} GB"}
    return render_template('system_security.html', info=info)

@app.route('/assessment', methods=['GET', 'POST'])
@login_required
def assessment():
    audit = None
    if request.method == 'POST':
        p = request.form.get('password_check','')
        s = sum([1 for r in [r"[A-Z]", r"[0-9]", r"[!@#]"] if re.search(r, p)]) + (1 if len(p)>=8 else 0)
        audit = {'password': p, 'score': s, 'verdict': "MẠNH" if s==4 else "YẾU"}
    return render_template('assessment.html', audit=audit)

@app.route('/hmac', methods=['GET', 'POST'])
@login_required
def hmac_tool():
    res = None
    if request.method == 'POST': res = hmac.new(request.form.get('key').encode(), request.form.get('data').encode(), hashlib.sha256).hexdigest()
    return render_template('hmac.html', result=res)

@app.route('/pentest_red', methods=['GET', 'POST'])
@login_required
def pentest_red():
    conn = sqlite3.connect(':memory:')
    conn.cursor().execute("CREATE TABLE u (u TEXT, p TEXT, f TEXT)").execute("INSERT INTO u VALUES ('admin','123','FLAG{SQL_WIN}')")
    res, q = None, ""
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
    return render_template('pentest_red.html', result=res, query=q)

@app.route('/pentest_blue')
@login_required
def pentest_blue():
    l = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()
    c = AuditLog.query.filter(AuditLog.action.contains('Attack')).count()
    return render_template('pentest_blue.html', logs=l, stats={'total':AuditLog.query.count(),'attacks':c})

@app.route('/rsa', methods=['GET', 'POST'])
@login_required
def rsa_tool(): return render_template('rsa.html')

@app.route('/about')
def about(): return render_template('about.html')

# --- MODULE AI: PHISHING DETECTOR ---
@app.route('/ai_phishing', methods=['GET', 'POST'])
@login_required
def ai_phishing():
    result = None
    prob = 0
    url_input = ""
    
    if request.method == 'POST':
        url_input = request.form.get('url')
        try:
            # Load model đã train
            if not os.path.exists('phishing_model.pkl'):
                flash('Chưa tìm thấy model AI! Hãy chạy file train_model.py trước.', 'danger')
            else:
                model = joblib.load('phishing_model.pkl')
                
                # AI Dự đoán
                # predict: Trả về 0 (An toàn) hoặc 1 (Độc hại)
                prediction = model.predict([url_input])[0] 
                
                # predict_proba: Trả về xác suất (ví dụ: 0.95 tức là 95% độc hại)
                probability = model.predict_proba([url_input])[0][1]
                prob = round(probability * 100, 2)
                
                if prediction == 1 or prob > 50:
                    result = "PHISHING (NGUY HIỂM)"
                    log_action(f'AI Alert: Phishing URL detected - {url_input}')
                else:
                    result = "SAFE (AN TOÀN)"
                    
        except Exception as e:
            result = f"Lỗi AI: {str(e)}"
            
    return render_template('ai_phishing.html', result=result, prob=prob, url=url_input)
# --- MODULE THREAT INTELLIGENCE ---
@app.route('/threat_intel', methods=['GET', 'POST'])
@login_required
def threat_intel():
    data = None
    error = None

    if request.method == 'POST':
        ip = request.form.get('ip_address')

        # Cấu hình gửi request lên AbuseIPDB
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '90' # Kiểm tra lịch sử trong 90 ngày
        }
        headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_KEY
        }

        try:
            response = requests.get(url, headers=headers, params=querystring)
            if response.status_code == 200:
                # Lấy dữ liệu thành công
                result = response.json()
                data = result['data']
            elif response.status_code == 401:
                error = "Lỗi API Key: Vui lòng kiểm tra lại Key trong code."
            elif response.status_code == 429:
                error = "Bạn đã hết lượt check miễn phí trong ngày."
            else:
                error = f"Lỗi không xác định: {response.status_code}"
        except Exception as e:
            error = f"Lỗi kết nối: {str(e)}"

    return render_template('threat_intel.html', data=data, error=error)    
# --- MAIN: TẠO DATABASE & CHALLENGES ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # 1. Tạo Admin
        if not User.query.filter_by(username='admin').first():
            db.session.add(User(username='admin', password=generate_password_hash('admin123'), role='admin', totp_secret=pyotp.random_base32()))
        
        # 2. Tạo CTF Challenges
        if Challenge.query.count() == 0:
            chal1 = Challenge(title="SQL Injection Basic", description="Tìm Flag ẩn trong module Red Team SQL Lab.", flag="FLAG{SQL_WIN}", points=100, category="Web")
            chal2 = Challenge(title="Hidden in Plain Sight", description="Tìm Flag bị giấu trong source code của trang chủ (Inspect Element).", flag="FLAG{HTML_MASTER}", points=50, category="Misc")
            chal3 = Challenge(title="Stego 101", description="Tải ảnh logo về, có một thông điệp ẩn trong đó.", flag="FLAG{PIXELS_DONT_LIE}", points=200, category="Forensics")
            db.session.add_all([chal1, chal2, chal3])
        
        db.session.commit()
        print(">>> Database Initialized with CTF Challenges.")

    app.run(debug=True, port=5000)