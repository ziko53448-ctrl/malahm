from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, send_from_directory
from functools import wraps
from pathlib import Path
import os
import json
import time
import hashlib
import shutil
from datetime import datetime, date
from werkzeug.utils import secure_filename
from PIL import Image, ImageOps
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
import sqlite3

app = Flask(__name__)
app.secret_key = "malahm_secret_2024_family_docs"
UPLOAD_FOLDER = Path("uploads")
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf', 'bmp', 'webp'}
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB

UPLOAD_FOLDER.mkdir(exist_ok=True)

# ==================== Database ====================
DB_FILE = "malahm.db"

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        user_id TEXT UNIQUE NOT NULL,
        name_ar TEXT,
        department TEXT,
        salt TEXT NOT NULL,
        pin_hash TEXT NOT NULL,
        created_at TEXT,
        updated_at TEXT
    )''')
    
    # Family members
    c.execute('''CREATE TABLE IF NOT EXISTS members (
        id INTEGER PRIMARY KEY,
        user_id TEXT NOT NULL,
        member_id TEXT UNIQUE NOT NULL,
        full_name_ar TEXT,
        relation TEXT,
        passport_no TEXT,
        passport_expiry TEXT,
        iqama_no TEXT,
        iqama_expiry TEXT,
        license_no TEXT,
        license_expiry TEXT,
        updated_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(user_id)
    )''')
    
    # Attachments
    c.execute('''CREATE TABLE IF NOT EXISTS attachments (
        id INTEGER PRIMARY KEY,
        member_id TEXT NOT NULL,
        kind TEXT,
        file_path TEXT,
        uploaded_at TEXT,
        FOREIGN KEY(member_id) REFERENCES members(member_id)
    )''')
    
    # Audit
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY,
        user_id TEXT NOT NULL,
        member_name TEXT,
        action TEXT,
        field TEXT,
        before_val TEXT,
        after_val TEXT,
        note TEXT,
        ts TEXT,
        FOREIGN KEY(user_id) REFERENCES users(user_id)
    )''')
    
    conn.commit()
    conn.close()

# ==================== Utilities ====================
def pbkdf2_hash_pin(pin: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, 120_000)
    return dk.hex()

def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def days_until(d):
    if not d:
        return None
    try:
        y, m, dd = map(int, d.split("-"))
        target = date(y, m, dd)
        return (target - date.today()).days
    except:
        return None

def expiry_badge(days):
    if days is None:
        return ("", "غير محدد")
    if days < 0:
        return ("⛔", f"منتهي منذ {-days} يوم")
    if days <= 60:
        return ("⚠", f"باقي {days} يوم")
    return ("✅", f"باقي {days} يوم")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def image_to_a4_pdf(img_path, out_pdf, title=""):
    img = Image.open(img_path)
    img = ImageOps.exif_transpose(img).convert("RGB")
    
    c = canvas.Canvas(str(out_pdf), pagesize=A4)
    page_w, page_h = A4
    
    top_margin = 36
    if title:
        c.setFont("Helvetica", 11)
        c.drawRightString(page_w - 36, page_h - 24, title)
        top_margin = 54
    
    margin = 36
    avail_w = page_w - 2 * margin
    avail_h = page_h - (margin + top_margin)
    
    img_w, img_h = img.size
    scale = min(avail_w / img_w, avail_h / img_h)
    draw_w = img_w * scale
    draw_h = img_h * scale
    
    x = (page_w - draw_w) / 2
    y = (page_h - top_margin - draw_h) / 2
    
    c.drawImage(ImageReader(img), x, y, width=draw_w, height=draw_h, preserveAspectRatio=True, anchor='c')
    c.showPage()
    c.save()

def audit_event(user_id, member_name, action, field="", before="", after="", note=""):
    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO audit_log (user_id, member_name, action, field, before_val, after_val, note, ts)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
              (user_id, member_name, action, field, before, after, note, now_iso()))
    conn.commit()
    conn.close()

# ==================== Auth ====================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        user_id = data.get('user_id', '').strip()
        pin = data.get('pin', '')
        
        if not user_id or not pin:
            return jsonify({'error': 'الرقم الوظيفي والرقم السري مطلوبان'}), 400
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
        user = c.fetchone()
        
        if not user:
            # First time: create user
            salt = os.urandom(16)
            pin_hash = pbkdf2_hash_pin(pin, salt)
            c.execute('''INSERT INTO users (user_id, salt, pin_hash, created_at, updated_at)
                         VALUES (?, ?, ?, ?, ?)''',
                      (user_id, salt.hex(), pin_hash, now_iso(), now_iso()))
            conn.commit()
        else:
            salt = bytes.fromhex(user['salt'])
            if pbkdf2_hash_pin(pin, salt) != user['pin_hash']:
                conn.close()
                return jsonify({'error': 'الرقم السري غير صحيح'}), 401
        
        conn.close()
        session['user_id'] = user_id
        return jsonify({'success': True, 'redirect': url_for('dashboard')})
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ==================== Dashboard ====================
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    
    # Get user info
    c.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
    user = c.fetchone()
    
    # Get members
    c.execute('SELECT * FROM members WHERE user_id = ?', (user_id,))
    members = c.fetchall()
    
    members_data = []
    alerts = []
    warn_days = 60
    
    for m in members:
        p_days = days_until(m['passport_expiry'])
        l_days = days_until(m['license_expiry'])
        p_icon, p_txt = expiry_badge(p_days)
        l_icon, l_txt = expiry_badge(l_days)
        
        if p_days is not None and p_days <= warn_days:
            alerts.append(f"{p_icon} جواز ({m['full_name_ar']}) — {m['passport_expiry']} — {p_txt}")
        if l_days is not None and l_days <= warn_days:
            alerts.append(f"{l_icon} رخصة ({m['full_name_ar']}) — {m['license_expiry']} — {l_txt}")
        
        members_data.append({
            'member_id': m['member_id'],
            'full_name_ar': m['full_name_ar'],
            'relation': m['relation'],
            'passport_expiry': m['passport_expiry'],
            'license_expiry': m['license_expiry'],
            'passport_badge': (p_icon, p_txt),
            'license_badge': (l_icon, l_txt),
        })
    
    conn.close()
    
    return render_template('dashboard.html', 
                          user=user,
                          members=members_data,
                          alerts=alerts)

# ==================== Members ====================
@app.route('/api/member/add', methods=['POST'])
@login_required
def add_member():
    user_id = session['user_id']
    data = request.get_json()
    member_name = data.get('name', '').strip()
    
    if not member_name:
        return jsonify({'error': 'اسم الفرد مطلوب'}), 400
    
    member_id = f"m_{int(time.time())}"
    
    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO members (user_id, member_id, full_name_ar, updated_at)
                 VALUES (?, ?, ?, ?)''',
              (user_id, member_id, member_name, now_iso()))
    conn.commit()
    conn.close()
    
    audit_event(user_id, member_name, 'CREATE_MEMBER')
    
    return jsonify({'success': True, 'member_id': member_id})

@app.route('/member/<member_id>')
@login_required
def member_profile(member_id):
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT * FROM members WHERE member_id = ? AND user_id = ?', (member_id, user_id))
    member = c.fetchone()
    
    if not member:
        return redirect(url_for('dashboard'))
    
    c.execute('SELECT * FROM attachments WHERE member_id = ?', (member_id,))
    attachments = c.fetchall()
    
    conn.close()
    
    return render_template('member.html', member=member, attachments=attachments)

@app.route('/api/member/<member_id>/update', methods=['POST'])
@login_required
def update_member(member_id):
    user_id = session['user_id']
    data = request.get_json()
    
    conn = get_db()
    c = conn.cursor()
    
    # Verify ownership
    c.execute('SELECT * FROM members WHERE member_id = ? AND user_id = ?', (member_id, user_id))
    member = c.fetchone()
    
    if not member:
        conn.close()
        return jsonify({'error': 'غير مصرح'}), 403
    
    # Update fields
    fields = ['full_name_ar', 'relation', 'passport_no', 'passport_expiry', 
              'iqama_no', 'iqama_expiry', 'license_no', 'license_expiry']
    
    updates = {}
    for field in fields:
        if field in data:
            new_val = data[field]
            old_val = member[field] or ""
            if new_val != old_val:
                audit_event(user_id, member['full_name_ar'], 'UPDATE_FIELD', field, old_val, new_val)
            updates[field] = new_val
    
    if updates:
        updates['updated_at'] = now_iso()
        set_clause = ', '.join([f"{k} = ?" for k in updates.keys()])
        c.execute(f'UPDATE members SET {set_clause} WHERE member_id = ?',
                  list(updates.values()) + [member_id])
        conn.commit()
    
    conn.close()
    return jsonify({'success': True})

# ==================== File Upload ====================
@app.route('/api/member/<member_id>/upload', methods=['POST'])
@login_required
def upload_attachment(member_id):
    user_id = session['user_id']
    
    conn = get_db()
    c = conn.cursor()
    
    # Verify ownership
    c.execute('SELECT * FROM members WHERE member_id = ? AND user_id = ?', (member_id, user_id))
    member = c.fetchone()
    conn.close()
    
    if not member:
        return jsonify({'error': 'غير مصرح'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': 'لا يوجد ملف'}), 400
    
    file = request.files['file']
    kind = request.form.get('kind', 'other')
    
    if file.filename == '':
        return jsonify({'error': 'اسم الملف فارغ'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'نوع ملف غير مسموح'}), 400
    
    if len(file.read()) > MAX_FILE_SIZE:
        return jsonify({'error': 'حجم الملف كبير جداً'}), 400
    
    file.seek(0)
    
    # Save file
    member_dir = UPLOAD_FOLDER / member_id
    member_dir.mkdir(exist_ok=True)
    
    filename = secure_filename(f"{kind}_{member['full_name_ar']}.{file.filename.rsplit('.', 1)[1].lower()}")
    filepath = member_dir / filename
    file.save(filepath)
    
    # Save to DB
    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO attachments (member_id, kind, file_path, uploaded_at)
                 VALUES (?, ?, ?, ?)''',
              (member_id, kind, str(filepath), now_iso()))
    conn.commit()
    conn.close()
    
    audit_event(user_id, member['full_name_ar'], 'ADD_ATTACHMENT', f'attachments.{kind}', '', str(filepath))
    
    return jsonify({'success': True, 'file_path': str(filepath)})

@app.route('/api/audit')
@login_required
def get_audit_log():
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''SELECT * FROM audit_log WHERE user_id = ? ORDER BY ts DESC LIMIT 500''', (user_id,))
    events = c.fetchall()
    conn.close()
    
    return render_template('audit.html', events=events)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
    
