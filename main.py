from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
from datetime import datetime, timedelta
import cv2
import numpy as np
from urllib.parse import parse_qs, urlparse
import random
import string
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super_secret_key_change_this_immediately'

# --- DATABASE CONFIGURATION (PostgreSQL) ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://okay_9pde_user:CV4rYVwQlfKoz38aZYuvIapAMxTjGir6@dpg-d63etfkhg0os73cej3j0-a.singapore-postgres.render.com/okay_9pde'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- REMEMBER ME CONFIGURATION (30 Days) ---
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # Session will expire in 30 mins

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- API CONFIGURATION ---
API_BASE_URL = "https://xgodo.com/api/v2/tasks"
API_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY5NzdhMDIxOTQxY2VkY2RjOTg4NmE2MSIsInVzZXJuYW1lIjoiaXRhY2hpdWNoaWhhYTI4Y3h0ZyIsImlhdCI6MTc2OTQ0NzQ1NywiZXhwIjo0ODkzNjQ5ODU3fQ.RWovXNp8xAKl6ZbiM5hZf1JHV8MT1vUpTn09NN0lbbo"
HEADERS = {"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"}
FIXED_JOB_ID = "69339726ce0295f74e58fe84"

# --- DATABASE MODELS ---

class SystemSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True)
    value = db.Column(db.String(50))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    coins = db.Column(db.Integer, default=0)
    last_auto_sync = db.Column(db.DateTime, nullable=True)
    tasks = db.relationship('Task', backref='owner', lazy=True)
    withdrawals = db.relationship('Withdrawal', backref='user', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    external_task_id = db.Column(db.String(100))
    job_id = db.Column(db.String(100))
    job_proof = db.Column(db.String(500))
    status = db.Column(db.String(50), default='pending')
    added_time = db.Column(db.String(50))
    updated_time = db.Column(db.String(50))
    last_synced = db.Column(db.String(50), nullable=True)
    reward_given = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Withdrawal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Integer, nullable=False)
    method = db.Column(db.String(50), nullable=False)
    account_details = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='pending')
    txid = db.Column(db.String(100), nullable=True)
    date = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- HELPER FUNCTIONS ---

def get_setting(key, default_val='false'):
    setting = SystemSetting.query.filter_by(key=key).first()
    return setting.value if setting else default_val

def set_setting(key, value):
    setting = SystemSetting.query.filter_by(key=key).first()
    if not setting:
        db.session.add(SystemSetting(key=key, value=value))
    else:
        setting.value = value
    db.session.commit()

def extract_secret_from_qr(image_stream):
    try:
        file_bytes = np.frombuffer(image_stream.read(), np.uint8)
        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(img)
        
        if data:
            parsed_url = urlparse(data)
            query_params = parse_qs(parsed_url.query)
            if 'secret' in query_params:
                return query_params['secret'][0].upper()
        return None
    except:
        return None

def generate_system_data():
    """পাসওয়ার্ড এবং রিকভারি ইমেইল অটো জেনারেট করে (সিস্টেম থেকে)"""
    chars = string.ascii_letters + string.digits
    password = "Pass@" + ''.join(random.choices(chars, k=5))
    rec_chars = string.ascii_lowercase + string.digits
    recovery = ''.join(random.choices(rec_chars, k=10)) + "@xneko.xyz"
    return password, recovery

# --- INTELLIGENT SYNC (AUTO ON LOGIN) ---

def sync_user_pending_tasks(user):
    pending_tasks = Task.query.filter(Task.user_id == user.id, Task.status.in_(['pending', 'processing'])).all()
    
    updates_count = 0
    for task in pending_tasks:
        try:
            response = requests.post(f"{API_BASE_URL}/details", params={'task_id': task.external_task_id}, headers=HEADERS)
            if response.status_code == 200:
                api_data = response.json()
                new_status = api_data.get('status', 'pending')
                
                if new_status != task.status:
                    task.status = new_status
                    task.updated_time = datetime.now().strftime("%Y-%m-%d")
                    task.last_synced = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    if new_status == 'confirmed' and not task.reward_given:
                        user.coins += 10
                        task.reward_given = True
                    elif new_status != 'confirmed' and task.reward_given:
                        user.coins -= 10
                        task.reward_given = False
                    
                    updates_count += 1
        except Exception as e:
            print(f"Sync Error for Task {task.id}: {e}")
            
    if updates_count > 0:
        db.session.commit()
    return updates_count

# --- CONTEXT PROCESSOR & MIDDLEWARE ---

@app.context_processor
def inject_settings():
    return dict(
        maintenance_mode=get_setting('maintenance_mode') == 'true',
        stop_task=get_setting('stop_task') == 'true',
        stop_withdraw=get_setting('stop_withdraw') == 'true'
    )

@app.before_request
def check_maintenance():
    if request.endpoint in ['static', 'login', 'logout', 'maintenance']: return
    if get_setting('maintenance_mode') == 'true':
        if not current_user.is_authenticated or not current_user.is_admin:
            return render_template('maintenance.html')
            
    # Session handling: Make session permanent so it lasts after browser close (for a while)
    session.permanent = True

# --- ROUTES ---

@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            if user.is_banned:
                flash('🚫 Account BANNED!')
                return render_template('login.html')
            
            login_user(user, remember=remember)
            
            # --- ADMIN CHECK ---
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            
            # --- AUTO SYNC FOR REGULAR USERS ---
            should_sync = False
            if user.last_auto_sync is None:
                should_sync = True
            else:
                time_diff = datetime.now() - user.last_auto_sync
                if time_diff.total_seconds() > 3600:
                    should_sync = True
            
            if should_sync:
                count = sync_user_pending_tasks(user)
                user.last_auto_sync = datetime.now()
                db.session.commit()
                if count > 0:
                    flash(f"🔄 Welcome back! {count} tasks synced.")
            
            return redirect(url_for('dashboard'))
        
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if get_setting('maintenance_mode') == 'true':
        return render_template('maintenance.html')

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))
        
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

# --- USER DASHBOARD ---

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    user_tasks = Task.query.filter_by(user_id=current_user.id).all()
    user_withdrawals = Withdrawal.query.filter_by(user_id=current_user.id).all()
    
    total_submitted = len(user_tasks)
    pending_tasks = sum(1 for t in user_tasks if t.status in ['pending', 'processing'])
    
    active_balance = current_user.coins
    hold_balance = pending_tasks * 10
    total_withdrawn = sum(w.amount for w in user_withdrawals if w.status in ['approved', 'pending'])
    total_earned = active_balance + total_withdrawn

    return render_template('dashboard.html', 
                           total=total_submitted, 
                           active_balance=active_balance, 
                           hold_balance=hold_balance, 
                           total_withdrawn=total_withdrawn,
                           total_earned=total_earned)

@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit_task():
    # Admin Protection
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    if get_setting('stop_task') == 'true':
        flash("⚠️ Task submission is currently PAUSED by Admin.")
        return redirect(url_for('dashboard'))

    # --- RESET / NEW TASK LOGIC ---
    if request.args.get('action') == 'reset':
        session.pop('task_session', None)
        flash("🔄 Started fresh!")
        return redirect(url_for('submit_task'))

    # --- STEP 1: INITIALIZE SESSION (EMAIL INPUT) ---
    if request.method == 'POST' and 'step_email' in request.form:
        email = request.form.get('step_email')

        # Check existing
        existing_tasks = Task.query.filter(Task.job_proof.like(f"{email}:%")).all()
        for t in existing_tasks:
            if t.status in ['pending', 'processing', 'confirmed']:
                flash(f"❌ Email '{email}' is already active in system.")
                return redirect(url_for('submit_task'))
        
        # Generate and Save to Session
        gen_pass, gen_recovery = generate_system_data()
        session['task_session'] = {
            'email': email,
            'password': gen_pass,
            'recovery': gen_recovery
        }
        # Redirect to GET to avoid resubmission issues
        return redirect(url_for('submit_task'))

    # --- STEP 2: FINAL SUBMISSION (FROM SESSION) ---
    if request.method == 'POST' and 'secret_code' in request.form:
        # Get data from session
        task_data = session.get('task_session')
        
        if not task_data:
            flash("❌ Session expired. Please start again.")
            return redirect(url_for('submit_task'))
            
        email = task_data['email']
        password = task_data['password']
        recovery_email = task_data['recovery']
        secret_code = request.form.get('secret_code')

        if not secret_code:
            flash("❌ Missing QR Code!")
            return redirect(url_for('submit_task'))
            
        formatted_proof = f"{email}:{password}:{recovery_email}:{secret_code.upper()}"
        payload = {"job_id": FIXED_JOB_ID, "job_proof": formatted_proof}

        try:
            response = requests.post(f"{API_BASE_URL}/submit", json=payload, headers=HEADERS)
            data = response.json()

            if response.status_code == 201 or 'job_task_id' in data:
                new_task = Task(
                    external_task_id=data.get('job_task_id'),
                    job_id=FIXED_JOB_ID,
                    job_proof=formatted_proof,
                    status='pending',
                    added_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    last_synced="Never",
                    owner=current_user
                )
                db.session.add(new_task)
                db.session.commit()
                
                # CLEAR SESSION ON SUCCESS
                session.pop('task_session', None)
                
                flash(f'✅ Task Submitted Successfully!')
                return redirect(url_for('my_tasks'))
            else:
                flash(f"API Error: {data}")
        except Exception as e:
            flash(f"Failed: {str(e)}")
        
        return redirect(url_for('submit_task'))

    # --- GET REQUEST (RENDER) ---
    # Retrieve session data to decide which view to show
    task_data = session.get('task_session')
    return render_template('submit_task.html', task_data=task_data)

@app.route('/my_tasks')
@login_required
def my_tasks():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.id.desc()).all()
    return render_template('my_tasks.html', tasks=tasks)

@app.route('/refresh_status/<int:task_id>')
@login_required
def refresh_status(task_id):
    task = Task.query.get_or_404(task_id)
    
    if task.user_id != current_user.id and not current_user.is_admin:
        return redirect(url_for('my_tasks'))

    # Permanent Lock
    if task.status == 'confirmed':
        flash("🔒 Task is CONFIRMED and permanently locked.")
        return redirect(url_for('my_tasks'))

    # Rate Limit (10 mins)
    if not current_user.is_admin and task.last_synced and task.last_synced != "Never":
        try:
            last_time = datetime.strptime(task.last_synced, "%Y-%m-%d %H:%M:%S")
            time_diff = datetime.now() - last_time
            if time_diff.total_seconds() < 600:
                flash(f"⏳ Please wait before syncing again.")
                return redirect(url_for('my_tasks'))
        except:
            pass

    try:
        response = requests.post(f"{API_BASE_URL}/details", params={'task_id': task.external_task_id}, headers=HEADERS)
        if response.status_code == 200:
            api_data = response.json()
            new_status = api_data.get('status', 'pending')
            
            task.updated_time = api_data.get('updated', datetime.now().strftime("%Y-%m-%d"))
            task.last_synced = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if new_status == 'confirmed' and not task.reward_given:
                task.owner.coins += 10
                task.reward_given = True
                flash("🎉 Confirmed! +10 Coins. Locked.")
            elif new_status != 'confirmed' and task.reward_given:
                task.owner.coins -= 10
                task.reward_given = False
                flash("⚠️ Status Changed. -10 Coins.")
            
            task.status = new_status
            db.session.commit()
        else:
            flash("⚠️ Sync Failed.")
    except Exception as e:
        flash(f"Error: {str(e)}")

    if current_user.is_admin and request.referrer:
        return redirect(request.referrer)
    return redirect(url_for('my_tasks'))

@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
        
    if get_setting('stop_withdraw') == 'true':
        flash("🚫 Withdrawals are currently PAUSED by Admin.")
        return redirect(url_for('dashboard'))

    min_amount = int(get_setting('min_withdraw', '10'))
    withdrawals = Withdrawal.query.filter_by(user_id=current_user.id).order_by(Withdrawal.id.desc()).all()

    if request.method == 'POST':
        amount = int(request.form.get('amount'))
        method = request.form.get('method')
        account = request.form.get('account')
        
        if amount < min_amount:
            flash(f"❌ Minimum withdrawal is {min_amount} coins.")
        elif current_user.coins < amount:
            flash("❌ Insufficient balance!")
        else:
            current_user.coins -= amount
            new_withdraw = Withdrawal(
                amount=amount,
                method=method,
                account_details=account,
                date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                user=current_user
            )
            db.session.add(new_withdraw)
            db.session.commit()
            flash("✅ Request Submitted!")
            return redirect(url_for('withdraw'))
            
    return render_template('withdraw.html', withdrawals=withdrawals, min_amount=min_amount)

@app.route('/see', methods=['GET'])
def see_user_data():
    user_id = request.args.get('id')
    if not user_id: return jsonify({'error': 'User ID required'}), 400
    
    user = User.query.get(user_id)
    if not user: return jsonify({'error': 'User not found'}), 404
    
    tasks = Task.query.filter_by(user_id=user_id).order_by(Task.id.desc()).all()
    t_list = []
    for t in tasks:
        t_list.append({
            'task_id': t.external_task_id, 'job_proof': t.job_proof, 
            'status': t.status, 'added_time': t.added_time
        })
    
    return jsonify({
        'user_id': user.id, 'username': user.username, 'coins': user.coins,
        'total_tasks': len(tasks), 'tasks': t_list
    })

@app.route('/api/process_qr', methods=['POST'])
@login_required
def process_qr():
    if 'qr_file' not in request.files: return jsonify({'success': False, 'error': 'No file'})
    file = request.files['qr_file']
    secret = extract_secret_from_qr(file)
    if secret: return jsonify({'success': True, 'secret': secret})
    else: return jsonify({'success': False, 'error': 'Failed'})

# --- ADMIN PANEL ROUTES ---

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin: return "Access Denied!", 403
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("🚫 Access Denied!")
        return redirect(url_for('dashboard'))

    total_users = User.query.count()
    total_tasks = Task.query.count()
    pending_withdrawals = Withdrawal.query.filter_by(status='pending').count()
    
    all_users = User.query.all()
    total_user_balance = sum(u.coins for u in all_users)
    pending_withdraw_amount = sum(w.amount for w in Withdrawal.query.filter_by(status='pending').all())

    return render_template('admin_dashboard.html', 
                           total_users=total_users, 
                           total_tasks=total_tasks, 
                           pending_withdrawals=pending_withdrawals,
                           total_user_balance=total_user_balance,
                           pending_withdraw_amount=pending_withdraw_amount)

@app.route('/admin/system', methods=['GET', 'POST'])
@login_required
def admin_system():
    if not current_user.is_admin: return "Access Denied", 403
    
    if request.method == 'POST':
        set_setting('maintenance_mode', 'true' if request.form.get('maintenance_mode') else 'false')
        set_setting('stop_task', 'true' if request.form.get('stop_task') else 'false')
        set_setting('stop_withdraw', 'true' if request.form.get('stop_withdraw') else 'false')
        flash("✅ Settings Updated!")
        return redirect(url_for('admin_system'))
        
    return render_template('admin_system.html')

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin: return "Access Denied", 403
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/ban_user/<int:user_id>/<string:action>')
@login_required
def ban_user(user_id, action):
    if not current_user.is_admin: return "Access Denied", 403
    user = User.query.get_or_404(user_id)
    if user.username != 'admin':
        user.is_banned = (action == 'ban')
        db.session.commit()
    flash(f"User {action}ned successfully.")
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>')
@login_required
def admin_user_profile(user_id):
    if not current_user.is_admin: return "Access Denied", 403
    user = User.query.get_or_404(user_id)
    tasks = Task.query.filter_by(user_id=user.id).all()
    withdrawals = Withdrawal.query.filter_by(user_id=user.id).all()
    return render_template('admin_user_profile.html', user=user, tasks=tasks, withdrawals=withdrawals)

@app.route('/admin/withdrawals', methods=['GET', 'POST'])
@login_required
def admin_withdrawals():
    if not current_user.is_admin: return "Access Denied", 403
    
    if request.method == 'POST':
        set_setting('min_withdraw', request.form.get('min_withdraw'))
        flash("Limit updated.")
        
    withdrawals = Withdrawal.query.order_by(Withdrawal.status.asc(), Withdrawal.id.desc()).all()
    min_withdraw = int(get_setting('min_withdraw', '10'))
    return render_template('admin_withdrawals.html', withdrawals=withdrawals, min_withdraw=min_withdraw)

@app.route('/admin/withdraw_action/<int:wid>', methods=['POST'])
@login_required
def withdraw_action(wid):
    if not current_user.is_admin: return "Access Denied", 403
    w = Withdrawal.query.get_or_404(wid)
    action = request.form.get('action')
    
    if action == 'approve':
        w.status = 'approved'
        w.txid = request.form.get('txid') or "N/A"
        flash("✅ Approved!")
    elif action == 'reject':
        w.user.coins += w.amount
        w.status = 'rejected'
        flash("❌ Rejected.")
        
    db.session.commit()
    return redirect(url_for('admin_withdrawals'))

@app.route('/admin/custom_task', methods=['GET', 'POST'])
@login_required
def admin_custom_task():
    if not current_user.is_admin: return "Access Denied", 403
    users = User.query.all()
    
    if request.method == 'POST':
        target_user_id = request.form.get('user_id')
        external_task_id = request.form.get('task_id')
        
        target_user = User.query.get(target_user_id)
        if target_user:
            try:
                response = requests.post(f"{API_BASE_URL}/details", params={'task_id': external_task_id}, headers=HEADERS)
                real_status = response.json().get('status', 'pending') if response.status_code == 200 else 'pending'
                
                new_task = Task(
                    external_task_id=external_task_id, 
                    job_id=FIXED_JOB_ID, 
                    job_proof="Added by Admin",
                    status=real_status, 
                    added_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    last_synced="Never", 
                    owner=target_user
                )
                
                if real_status == 'confirmed':
                    target_user.coins += 10
                    new_task.reward_given = True
                    flash("✅ Added & Confirmed.")
                else:
                    flash(f"ℹ️ Added with status: {real_status}")
                    
                db.session.add(new_task)
                db.session.commit()
            except Exception as e:
                flash(f"Error: {e}")
                
    return render_template('admin_custom_task.html', users=users)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create Default Admin
        if not User.query.filter_by(username='admin').first():
            db.session.add(User(username='admin', password='admin123', is_admin=True))
        # Create Default Settings
        if not SystemSetting.query.filter_by(key='min_withdraw').first():
            db.session.add(SystemSetting(key='min_withdraw', value='10'))
        db.session.commit()
        
    app.run(host='0.0.0.0', port=8080, debug=True)
