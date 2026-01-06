from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
import nvdlib
import datetime
import os
import requests
from dotenv import load_dotenv

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_dev_key')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Database Model ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='readonly') # 'admin' or 'readonly'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    cpe = db.Column(db.String(200), nullable=False)
    last_checked = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    vulnerabilities = db.relationship('Vulnerability', backref='device', lazy=True, cascade="all, delete-orphan")

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=True)
    score = db.Column(db.String(10), nullable=True)
    severity = db.Column(db.String(20), nullable=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)

    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)

class SystemSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=True)

    @staticmethod
    def get_setting(key, default=None):
        setting = SystemSettings.query.filter_by(key=key).first()
        return setting.value if setting else default

    @staticmethod
    def set_setting(key, value):
        setting = SystemSettings.query.filter_by(key=key).first()
        if not setting:
            setting = SystemSettings(key=key)
            db.session.add(setting)
        setting.value = value
        db.session.commit()

@app.context_processor
def inject_settings():
    return dict(
        app_name=SystemSettings.get_setting('app_name', 'Patch Monitor Network'),
        app_icon=SystemSettings.get_setting('app_icon', 'fa-shield-halved'),
        navbar_color=SystemSettings.get_setting('navbar_color', 'blue')
    )

# --- Notification Functions (Stubs) ---
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- Notification Functions ---
def send_telegram(message):
    token = os.getenv('TELEGRAM_TOKEN')
    chat_id = os.getenv('TELEGRAM_CHAT_ID')
    if token and chat_id:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            requests.post(url, data={'chat_id': chat_id, 'text': message})
            print(f"[Telegram] Sent: {message}")
        except Exception as e:
            print(f"[Telegram] Error: {e}")
    else:
        print(f"[Telegram] Skipped (No credentials): {message}")

def send_email(subject, body):
    sender_email = os.getenv('EMAIL_USER')
    sender_password = os.getenv('EMAIL_PASS')
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    
    # Use explicit recipient if set, otherwise default to sender (self-email)
    receiver_email = os.getenv('EMAIL_RECIPIENT', sender_email)

    if not all([sender_email, sender_password, smtp_server]):
        print("[Email] Skipped: Missing SMTP configuration.")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()
        print(f"[Email] Sent successfully to {receiver_email}")
    except Exception as e:
        print(f"[Email] Error: {e}")

# --- Helper to Create Initial Admin ---
def create_initial_user():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            print("Creating default admin user...")
            admin = User(username='admin', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Default admin created: admin / admin123")
        
        if not User.query.filter_by(username='user').first():
            print("Creating default read-only user...")
            readonly_user = User(username='user', role='readonly')
            readonly_user.set_password('user123')
            db.session.add(readonly_user)
            db.session.commit()
            print("Default read-only user created: user / user123")

from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    devices = Device.query.all()
    return render_template('dashboard.html', devices=devices)

@app.route('/add', methods=['POST'])
@login_required
@admin_required
def add_device():
    hostname = request.form.get('hostname')
    cpe = request.form.get('cpe')
    if hostname and cpe:
        new_device = Device(hostname=hostname, cpe=cpe)
        db.session.add(new_device)
        db.session.commit()
        flash('Device added successfully!', 'success')
    else:
        flash('Hostname and CPE are required!', 'error')
    return redirect(url_for('dashboard'))

@app.route('/edit/<int:id>', methods=['POST'])
@login_required
@admin_required
def edit_device(id):
    device = Device.query.get_or_404(id)
    hostname = request.form.get('hostname')
    cpe = request.form.get('cpe')
    
    if hostname and cpe:
        device.hostname = hostname
        device.cpe = cpe
        db.session.commit()
        flash('Device updated successfully!', 'success')
    else:
        flash('Hostname and CPE are required!', 'error')
        
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:id>')
@login_required
@admin_required
def delete_device(id):
    device = Device.query.get_or_404(id)
    db.session.delete(device)
    db.session.commit()
    flash('Device deleted!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/scan-now')
@login_required
@admin_required
def scan_now():
    api_key = os.getenv('NIST_API_KEY')
    devices = Device.query.all()
    vulnerable_devices = []
    
    # Check CVEs modified in the last 24 hours (example logic)
    # nvdlib usually takes datetime objects or string dates
    end_date = datetime.datetime.now()
    start_date = end_date - datetime.timedelta(days=1)
    
    # Clear existing vulnerabilities for re-scan
    for device in devices:
        Vulnerability.query.filter_by(device_id=device.id).delete()
    
    # Note: nvdlib searchCVE format might vary, adjusting to standard usage:
    # We search specifically for the CPEs in our inventory
    for device in devices:
        try:
            # Search for ALL vulnerabilities for this CPE (no date filter)
            r = nvdlib.searchCVE(
                cpeName=device.cpe,
                key=api_key,
                limit=50
            )
            
            if r:
                device_alert = f"Found {len(r)} CVEs for {device.hostname} ({device.cpe})"
                vulnerable_devices.append(device_alert)
                
                # Update last checked
                device.last_checked = datetime.datetime.utcnow()
                
                for cve in r:
                    # Nvdlib object attributes check
                    cve_id = cve.id
                    description = cve.descriptions[0].value if hasattr(cve, 'descriptions') and cve.descriptions else "No description"
                    
                    # Score extraction (V3 or V2)
                    score = "N/A"
                    severity = "N/A"
                    
                    if hasattr(cve, 'v31score'):
                        score = str(cve.v31score)
                        severity = str(cve.v31severity).upper()
                    elif hasattr(cve, 'v30score'):
                        score = str(cve.v30score)
                        severity = str(cve.v30severity).upper()
                    elif hasattr(cve, 'v2score'):
                        score = str(cve.v2score)
                        severity = str(cve.v2severity).upper()

                    new_vuln = Vulnerability(
                        cve_id=cve_id,
                        description=description,
                        score=score,
                        severity=severity,
                        device_id=device.id
                    )
                    db.session.add(new_vuln)

                # Prepare notification details (Top 5 only for msg)
                cve_details = "\n".join([f"{x.id}: {x.v31score if hasattr(x, 'v31score') else 'N/A'}" for x in r[:5]])
                if len(r) > 5: cve_details += "\n...and more."
                
                send_telegram(f"🚨 ALERT: {device_alert}\n{cve_details}")
                
                # Format Email Body (Styled HTML)
                dashboard_url = url_for('monitoring', _external=True)
                
                email_body = f"""
                <html>
                <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f9; padding: 0; margin: 0;">
                    <!-- Top Warning Bar -->
                    <div style="background-color: #fbbf24; color: #000; padding: 10px; text-align: center; font-size: 14px; font-weight: bold; border-bottom: 1px solid #d97706;">
                        Please note: This is an automated security notification from the Patch Monitoring Network. Do not reply to this email.
                    </div>

                    <div style="max-width: 600px; margin: 20px auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden;">
                        
                        <!-- Logo/Brand Area (Placeholder for nice header) -->
                        <div style="padding: 20px; text-align: center; border-bottom: 3px solid #ef4444;">
                            <h1 style="color: #333; margin: 0; font-size: 28px; letter-spacing: 1px;">
                                <span style="color: #ef4444;">Patch Monitor</span> Network
                            </h1>
                            <p style="color: #666; margin: 5px 0 0 0; font-size: 14px;">Internal Cyber Security Alert System</p>
                        </div>
                        
                        <div style="padding: 30px;">
                            <h2 style="color: #ef4444; text-align: center; margin-top: 0; font-size: 22px; font-weight: normal;">
                                Critical Vulnerabilities Detected in {device.hostname}
                            </h2>
                            
                            <p style="font-size: 16px; color: #333; line-height: 1.6; text-align: center;">
                                New security updates are available to address vulnerabilities affecting 
                                <strong>{device.hostname}</strong> (<code style="background-color: #f3f4f6; padding: 2px 5px; border-radius: 4px;">{device.cpe}</code>).
                                Administrators are advised to review and update immediately.
                            </p>
                            
                            <div style="background-color: #fff1f2; border: 1px solid #fecaca; border-radius: 8px; padding: 20px; margin: 25px 0;">
                                <p style="margin: 0 0 10px 0; color: #991b1b; font-weight: bold; text-transform: uppercase; font-size: 13px;">Vulnerability Summary</p>
                                <ul style="padding-left: 20px; margin: 0; color: #444;">
                """
                for x in r[:5]:
                    score = x.v31score if hasattr(x, 'v31score') else 'N/A'
                    email_body += f"<li style='margin-bottom: 8px;'><strong>{x.id}</strong> (CVSS: {score}) - <a href='https://nvd.nist.gov/vuln/detail/{x.id}' style='color: #2563eb; text-decoration: none;'>View NIST</a></li>"
                
                email_body += """
                            </ul>
                            """
                if len(r) > 5:
                    email_body += f"<p style='color: #666; font-style: italic;'>...and {len(r)-5} more.</p>"
                
                email_body += f"""
                            <div style="text-align: center; margin-top: 30px;">
                                <a href="{dashboard_url}" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">View Monitoring Dashboard</a>
                            </div>
                        </div>
                        <div style="background-color: #f3f4f6; padding: 15px; text-align: center; font-size: 12px; color: #888;">
                            Patch Monitoring Network | Automated Alert System
                        </div>
                    </div>
                </body>
                </html>
                """
                
                send_email(f"🚨 Security Alert: {device.hostname} Vulnerable", email_body)

        except Exception as e:
            print(f"Error scanning {device.hostname}: {e}")
            flash(f"Error scanning {device.hostname}: {str(e)}", 'error')

    db.session.commit()
    
    if vulnerable_devices:
        flash(f"Scan complete. Vulnerabilities found for {len(vulnerable_devices)} devices. Check Monitoring page.", 'warning')
    else:
        flash("Scan complete. No active vulnerabilities found for these devices.", 'success')
        
    return redirect(url_for('monitoring'))
    
    if vulnerable_devices:
        flash(f"Scan complete. Vulnerabilities found: {len(vulnerable_devices)} devices affected.", 'warning')
    else:
        flash("Scan complete. No active vulnerabilities found for these devices.", 'success')
        
    return redirect(url_for('dashboard'))

@app.route('/test-email')
def test_email():
    try:
        send_email("Test Email from Patch Monitor", "<h1>It Works!</h1><p>Your SMTP settings are correct.</p>")
        flash("Test email sent! Check your inbox.", "success")
    except Exception as e:
        flash(f"Failed to send test email: {e}", "error")
    return redirect(url_for('dashboard'))

@app.route('/monitoring')
def monitoring():
    # Join Device and Vulnerability to get a flat list or grouped by device
    # Here we send devices and let template iterate vulnerabilities
    devices = Device.query.all()
    return render_template('monitoring.html', devices=devices)

# --- User Management Routes ---
@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/add', methods=['POST'])
@login_required
@admin_required
def add_user():
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists!', 'error')
    else:
        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully!', 'success')
        
    return redirect(url_for('manage_users'))

@app.route('/admin/users/delete/<int:id>')
@login_required
@admin_required
def delete_user(id):
    user = User.query.get_or_404(id)
    if user.username == 'admin':
        flash('Cannot delete the root admin user!', 'error')
    elif user.id == current_user.id:
        flash('You cannot delete yourself!', 'error')
    else:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    return redirect(url_for('manage_users'))

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not current_user.check_password(current_password):
        flash('Incorrect current password!', 'error')
        return redirect(request.referrer)

    if new_password != confirm_password:
        flash('New passwords do not match!', 'error')
        return redirect(request.referrer)

    current_user.set_password(new_password)
    db.session.commit()
    flash('Password changed successfully!', 'success')
    return redirect(request.referrer)

@app.route('/admin/users/reset-password/<int:id>', methods=['POST'])
@login_required
@admin_required
def reset_user_password(id):
    user = User.query.get_or_404(id)
    new_password = request.form.get('new_password')
    
    if new_password:
        user.set_password(new_password)
        db.session.commit()
        flash(f"Password for {user.username} has been reset.", 'success')
    else:
        flash("Password cannot be empty.", 'error')
        
    return redirect(url_for('manage_users'))

    return redirect(url_for('manage_users'))

@app.route('/admin/settings', methods=['POST'])
@login_required
@admin_required
def update_settings():
    app_name = request.form.get('app_name')
    app_icon = request.form.get('app_icon')
    navbar_color = request.form.get('navbar_color')

    if app_name:
        SystemSettings.set_setting('app_name', app_name)
    if app_icon:
        SystemSettings.set_setting('app_icon', app_icon)
    if navbar_color:
        SystemSettings.set_setting('navbar_color', navbar_color)

    flash('System settings updated successfully!', 'success')
    return redirect(url_for('manage_users'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_initial_user()
    app.run(debug=True, host='0.0.0.0', port=5001)
