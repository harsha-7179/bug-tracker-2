"""
Enhanced Bug Tracking Collaboration Website
A full-stack Flask application for collaborative bug tracking with group management,
notifications, forgot password, mobile responsiveness, and enhanced features
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime, timedelta
import uuid
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Email configuration (configure these for forgot password functionality)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-app-password'

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'txt', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_email(to_email, subject, body):
    """Send email notification"""
    try:
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        text = msg.as_string()
        server.sendmail(app.config['MAIL_USERNAME'], to_email, text)
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect('bug_tracker.db')
    c = conn.cursor()
    
    # Check if we need to migrate from old structure
    c.execute("PRAGMA table_info(users)")
    user_columns = [column[1] for column in c.fetchall()]
    
    # Users table - add new columns if they don't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Add reset token columns if they don't exist
    if 'reset_token' not in user_columns:
        c.execute('ALTER TABLE users ADD COLUMN reset_token TEXT')
    if 'reset_token_expires' not in user_columns:
        c.execute('ALTER TABLE users ADD COLUMN reset_token_expires TIMESTAMP')
    
    # Check if groups table exists and its structure
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='groups'")
    groups_exists = c.fetchone()
    
    if groups_exists:
        c.execute("PRAGMA table_info(groups)")
        group_columns = [column[1] for column in c.fetchall()]
        
        # If old structure exists with leader_id, keep it compatible
        if 'leader_id' in group_columns and 'creator_id' not in group_columns:
            print("Using existing group structure with leader_id")
        else:
            # Create new structure
            c.execute('''
                CREATE TABLE IF NOT EXISTS groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    leader_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (leader_id) REFERENCES users (id)
                )
            ''')
    else:
        # Create groups table with leader_id (compatible with original)
        c.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                leader_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (leader_id) REFERENCES users (id)
            )
        ''')
    
    # Group leaders table (for multiple leaders)
    c.execute('''
        CREATE TABLE IF NOT EXISTS group_leaders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (group_id) REFERENCES groups (id),
            UNIQUE(user_id, group_id)
        )
    ''')
    
    # Group invitations table
    c.execute('''
        CREATE TABLE IF NOT EXISTS group_invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            inviter_id INTEGER NOT NULL,
            invitee_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            responded_at TIMESTAMP,
            FOREIGN KEY (inviter_id) REFERENCES users (id),
            FOREIGN KEY (invitee_id) REFERENCES users (id),
            FOREIGN KEY (group_id) REFERENCES groups (id)
        )
    ''')
    
    # Group memberships table
    c.execute('''
        CREATE TABLE IF NOT EXISTS memberships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (group_id) REFERENCES groups (id),
            UNIQUE(user_id, group_id)
        )
    ''')
    
    # Check bugs table structure and add new columns
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='bugs'")
    bugs_exists = c.fetchone()
    
    if bugs_exists:
        c.execute("PRAGMA table_info(bugs)")
        bug_columns = [column[1] for column in c.fetchall()]
        
        # Add new columns if they don't exist
        if 'priority' not in bug_columns:
            c.execute('ALTER TABLE bugs ADD COLUMN priority TEXT DEFAULT "medium"')
        if 'approved_by' not in bug_columns:
            c.execute('ALTER TABLE bugs ADD COLUMN approved_by INTEGER')
        if 'last_edited' not in bug_columns:
            c.execute('ALTER TABLE bugs ADD COLUMN last_edited TIMESTAMP')
    else:
        # Create bugs table
        c.execute('''
            CREATE TABLE IF NOT EXISTS bugs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                reporter_id INTEGER NOT NULL,
                group_id INTEGER NOT NULL,
                status TEXT DEFAULT 'pending',
                priority TEXT DEFAULT 'medium',
                file_path TEXT,
                file_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                approved_at TIMESTAMP,
                approved_by INTEGER,
                last_edited TIMESTAMP,
                FOREIGN KEY (reporter_id) REFERENCES users (id),
                FOREIGN KEY (group_id) REFERENCES groups (id),
                FOREIGN KEY (approved_by) REFERENCES users (id)
            )
        ''')
    
    # Check suggestions table structure and add new columns
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='suggestions'")
    suggestions_exists = c.fetchone()
    
    if suggestions_exists:
        c.execute("PRAGMA table_info(suggestions)")
        suggestion_columns = [column[1] for column in c.fetchall()]
        
        if 'reviewed_by' not in suggestion_columns:
            c.execute('ALTER TABLE suggestions ADD COLUMN reviewed_by INTEGER')
    else:
        # Create suggestions table
        c.execute('''
            CREATE TABLE IF NOT EXISTS suggestions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                author_id INTEGER NOT NULL,
                group_id INTEGER NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP,
                reviewed_by INTEGER,
                FOREIGN KEY (author_id) REFERENCES users (id),
                FOREIGN KEY (group_id) REFERENCES groups (id),
                FOREIGN KEY (reviewed_by) REFERENCES users (id)
            )
        ''')
    
    # Notifications table
    c.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT NOT NULL,
            read_status INTEGER DEFAULT 0,
            related_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Migrate existing group leaders to new table
    c.execute("SELECT COUNT(*) FROM group_leaders")
    leader_count = c.fetchone()[0]
    
    if leader_count == 0:
        # Migrate existing group leaders
        c.execute('''
            INSERT OR IGNORE INTO group_leaders (user_id, group_id)
            SELECT leader_id, id FROM groups
        ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect('bug_tracker.db')
    conn.row_factory = sqlite3.Row
    return conn

def is_group_leader(user_id, group_id):
    """Check if user is a leader of the group"""
    conn = get_db_connection()
    leader = conn.execute(
        'SELECT id FROM group_leaders WHERE user_id = ? AND group_id = ?',
        (user_id, group_id)
    ).fetchone()
    conn.close()
    return leader is not None

def create_notification(user_id, title, message, notification_type, related_id=None):
    """Create a notification for a user"""
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO notifications (user_id, title, message, type, related_id) VALUES (?, ?, ?, ?, ?)',
        (user_id, title, message, notification_type, related_id)
    )
    conn.commit()
    conn.close()

def get_unread_notifications_count(user_id):
    """Get count of unread notifications for a user"""
    conn = get_db_connection()
    count = conn.execute(
        'SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND read_status = 0',
        (user_id,)
    ).fetchone()
    conn.close()
    return count['count'] if count else 0

@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration"""
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return render_template('signup.html')
        
        conn = get_db_connection()
        
        # Check if user already exists
        existing_user = conn.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            (username, email)
        ).fetchone()
        
        if existing_user:
            flash('Username or email already exists!', 'error')
            conn.close()
            return render_template('signup.html')
        
        # Create new user
        password_hash = generate_password_hash(password)
        conn.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            (username, email, password_hash)
        )
        conn.commit()
        conn.close()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password functionality"""
    if request.method == 'POST':
        username = request.form['username'].strip()
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user:
            # Generate reset token
            reset_token = str(uuid.uuid4())
            expires = datetime.now() + timedelta(hours=1)
            
            conn.execute(
                'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?',
                (reset_token, expires, user['id'])
            )
            conn.commit()
            
            # In production, send email with reset link
            reset_url = url_for('reset_password', token=reset_token, _external=True)
            flash(f'Password reset link: {reset_url} (In production, this would be emailed)', 'success')
        else:
            flash('Username not found!', 'error')
        
        conn.close()
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password with token"""
    conn = get_db_connection()
    user = conn.execute(
        'SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?',
        (token, datetime.now())
    ).fetchone()
    
    if not user:
        flash('Invalid or expired reset token!', 'error')
        conn.close()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
        elif len(password) < 6:
            flash('Password must be at least 6 characters!', 'error')
        else:
            password_hash = generate_password_hash(password)
            conn.execute(
                'UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
                (password_hash, user['id'])
            )
            conn.commit()
            conn.close()
            flash('Password reset successfully! Please log in.', 'success')
            return redirect(url_for('login'))
    
    conn.close()
    return render_template('reset_password.html', token=token)

@app.route('/notifications')
def notifications():
    """View notifications"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    notifications = conn.execute(
        'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    
    # Mark notifications as read
    conn.execute(
        'UPDATE notifications SET read_status = 1 WHERE user_id = ?',
        (session['user_id'],)
    )
    conn.commit()
    conn.close()
    
    return render_template('notifications.html', notifications=notifications)

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    """User dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get user's groups - use leader_id instead of creator_id for compatibility
    groups = conn.execute('''
        SELECT g.*, u.username as leader_name,
               CASE WHEN gl.user_id = ? THEN 1 ELSE 0 END as is_leader
        FROM groups g
        JOIN memberships m ON g.id = m.group_id
        JOIN users u ON g.leader_id = u.id
        LEFT JOIN group_leaders gl ON g.id = gl.group_id AND gl.user_id = ?
        WHERE m.user_id = ?
        ORDER BY g.name
    ''', (session['user_id'], session['user_id'], session['user_id'])).fetchall()
    
    # Get pending invitations
    invitations = conn.execute('''
        SELECT gi.*, g.name as group_name, u.username as inviter_name
        FROM group_invitations gi
        JOIN groups g ON gi.group_id = g.id
        JOIN users u ON gi.inviter_id = u.id
        WHERE gi.invitee_id = ? AND gi.status = 'pending'
        ORDER BY gi.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    notifications_count = get_unread_notifications_count(session['user_id'])
    
    conn.close()
    return render_template('dashboard.html', groups=groups, invitations=invitations, notifications_count=notifications_count)

@app.route('/create_group', methods=['GET', 'POST'])
def create_group():
    """Create a new group"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name'].strip()
        description = request.form['description'].strip()
        
        if not name:
            flash('Group name is required!', 'error')
            return render_template('create_group.html')
        
        conn = get_db_connection()
        
        # Create group with leader_id
        cursor = conn.execute(
            'INSERT INTO groups (name, description, leader_id) VALUES (?, ?, ?)',
            (name, description, session['user_id'])
        )
        group_id = cursor.lastrowid
        
        # Add creator as leader
        conn.execute(
            'INSERT INTO group_leaders (user_id, group_id) VALUES (?, ?)',
            (session['user_id'], group_id)
        )
        
        # Add creator as member
        conn.execute(
            'INSERT INTO memberships (user_id, group_id) VALUES (?, ?)',
            (session['user_id'], group_id)
        )
        
        conn.commit()
        conn.close()
        
        flash('Group created successfully!', 'success')
        return redirect(url_for('group_detail', group_id=group_id))
    
    return render_template('create_group.html')

@app.route('/group/<int:group_id>')
def group_detail(group_id):
    """Group detail page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Check if user is member of this group
    membership = conn.execute(
        'SELECT * FROM memberships WHERE user_id = ? AND group_id = ?',
        (session['user_id'], group_id)
    ).fetchone()
    
    if not membership:
        flash('You are not a member of this group!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Get group info - use leader_id for compatibility
    group = conn.execute(
        'SELECT g.*, u.username as leader_name FROM groups g JOIN users u ON g.leader_id = u.id WHERE g.id = ?',
        (group_id,)
    ).fetchone()
    
    # Get group members with leader status
    members = conn.execute('''
        SELECT u.id as user_id, u.username, m.joined_at, 
               CASE WHEN gl.user_id IS NOT NULL THEN gl.user_id ELSE NULL END as is_leader
        FROM memberships m
        JOIN users u ON m.user_id = u.id
        LEFT JOIN group_leaders gl ON m.user_id = gl.user_id AND m.group_id = gl.group_id
        WHERE m.group_id = ?
        ORDER BY gl.user_id DESC NULLS LAST, u.username
    ''', (group_id,)).fetchall()
    
    # Get bugs
    bugs = conn.execute('''
        SELECT b.*, u.username as reporter_name, approver.username as approved_by_name
        FROM bugs b
        JOIN users u ON b.reporter_id = u.id
        LEFT JOIN users approver ON b.approved_by = approver.id
        WHERE b.group_id = ?
        ORDER BY b.created_at DESC
    ''', (group_id,)).fetchall()
    
    # Get suggestions
    suggestions = conn.execute('''
        SELECT s.*, u.username as author_name, reviewer.username as reviewed_by_name
        FROM suggestions s
        JOIN users u ON s.author_id = u.id
        LEFT JOIN users reviewer ON s.reviewed_by = reviewer.id
        WHERE s.group_id = ?
        ORDER BY s.created_at DESC
    ''', (group_id,)).fetchall()
    
    is_leader = is_group_leader(session['user_id'], group_id)
    
    conn.close()
    return render_template('group_detail.html', 
                         group=group, members=members, bugs=bugs, 
                         suggestions=suggestions, is_leader=is_leader)

@app.route('/invite_user/<int:group_id>', methods=['POST'])
def invite_user(group_id):
    """Invite user to group"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    username = request.form['username'].strip()
    message = request.form.get('message', '').strip()
    
    conn = get_db_connection()
    
    # Check if current user is group leader
    if not is_group_leader(session['user_id'], group_id):
        flash('Only group leaders can invite users!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=group_id))
    
    # Find user to invite
    user_to_invite = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user_to_invite:
        flash('User not found!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=group_id))
    
    # Check if user is already a member
    existing_membership = conn.execute(
        'SELECT id FROM memberships WHERE user_id = ? AND group_id = ?',
        (user_to_invite['id'], group_id)
    ).fetchone()
    
    if existing_membership:
        flash('User is already a member of this group!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=group_id))
    
    # Check for existing invitation
    existing_invitation = conn.execute(
        'SELECT id FROM group_invitations WHERE invitee_id = ? AND group_id = ? AND status = "pending"',
        (user_to_invite['id'], group_id)
    ).fetchone()
    
    if existing_invitation:
        flash('User already has a pending invitation!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=group_id))
    
    # Get group name
    group = conn.execute('SELECT name FROM groups WHERE id = ?', (group_id,)).fetchone()
    
    # Create invitation
    conn.execute(
        'INSERT INTO group_invitations (inviter_id, invitee_id, group_id, message) VALUES (?, ?, ?, ?)',
        (session['user_id'], user_to_invite['id'], group_id, message)
    )
    
    # Create notification
    create_notification(
        user_to_invite['id'],
        'Group Invitation',
        f'{session["username"]} invited you to join "{group["name"]}"',
        'invitation',
        group_id
    )
    
    conn.commit()
    conn.close()
    
    flash(f'Invitation sent to {username}!', 'success')
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/respond_invitation/<int:invitation_id>/<response>')
def respond_invitation(invitation_id, response):
    """Accept or decline group invitation"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if response not in ['accept', 'decline']:
        flash('Invalid response!', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    
    # Get invitation
    invitation = conn.execute(
        'SELECT * FROM group_invitations WHERE id = ? AND invitee_id = ? AND status = "pending"',
        (invitation_id, session['user_id'])
    ).fetchone()
    
    if not invitation:
        flash('Invitation not found or already responded!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Update invitation status
    conn.execute(
        'UPDATE group_invitations SET status = ?, responded_at = CURRENT_TIMESTAMP WHERE id = ?',
        (response + 'd', invitation_id)
    )
    
    if response == 'accept':
        # Add user to group
        conn.execute(
            'INSERT INTO memberships (user_id, group_id) VALUES (?, ?)',
            (session['user_id'], invitation['group_id'])
        )
        flash('Successfully joined the group!', 'success')
    else:
        flash('Invitation declined.', 'info')
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard'))

@app.route('/make_leader/<int:group_id>/<int:user_id>')
def make_leader(group_id, user_id):
    """Make a user a leader of the group"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Check if current user is group leader
    if not is_group_leader(session['user_id'], group_id):
        flash('Only group leaders can assign new leaders!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=group_id))
    
    # Check if target user is a member
    membership = conn.execute(
        'SELECT * FROM memberships WHERE user_id = ? AND group_id = ?',
        (user_id, group_id)
    ).fetchone()
    
    if not membership:
        flash('User is not a member of this group!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=group_id))
    
    # Check if already a leader
    existing_leader = conn.execute(
        'SELECT * FROM group_leaders WHERE user_id = ? AND group_id = ?',
        (user_id, group_id)
    ).fetchone()
    
    if existing_leader:
        flash('User is already a leader!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=group_id))
    
    # Add as leader
    conn.execute(
        'INSERT INTO group_leaders (user_id, group_id) VALUES (?, ?)',
        (user_id, group_id)
    )
    
    # Get username for notification
    user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    group = conn.execute('SELECT name FROM groups WHERE id = ?', (group_id,)).fetchone()
    
    create_notification(
        user_id,
        'Leadership Assignment',
        f'You have been made a leader of "{group["name"]}"',
        'leadership',
        group_id
    )
    
    conn.commit()
    conn.close()
    
    flash(f'{user["username"]} has been made a leader!', 'success')
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/upload_bug/<int:group_id>', methods=['POST'])
def upload_bug(group_id):
    """Upload a bug report"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    title = request.form['title'].strip()
    description = request.form['description'].strip()
    priority = request.form.get('priority', 'medium')
    
    if not title or not description:
        flash('Title and description are required!', 'error')
        return redirect(url_for('group_detail', group_id=group_id))
    
    conn = get_db_connection()
    
    # Check if user is member of this group
    membership = conn.execute(
        'SELECT * FROM memberships WHERE user_id = ? AND group_id = ?',
        (session['user_id'], group_id)
    ).fetchone()
    
    if not membership:
        flash('You are not a member of this group!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    file_path = None
    file_name = None
    
    # Handle file upload
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to avoid conflicts
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            file_name = file.filename
            file_path = f'uploads/{filename}'  # Relative path for database
    
    # Insert bug report
    conn.execute('''
        INSERT INTO bugs (title, description, reporter_id, group_id, priority, file_path, file_name)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (title, description, session['user_id'], group_id, priority, file_path, file_name))
    
    conn.commit()
    conn.close()
    
    flash('Bug report submitted successfully!', 'success')
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/edit_bug/<int:bug_id>', methods=['GET', 'POST'])
def edit_bug(bug_id):
    """Edit a bug report"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get bug
    bug = conn.execute('''
        SELECT b.*, g.id as group_id
        FROM bugs b
        JOIN groups g ON b.group_id = g.id
        WHERE b.id = ?
    ''', (bug_id,)).fetchone()
    
    if not bug:
        flash('Bug not found!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Check if user can edit (reporter or leader)
    can_edit = (bug['reporter_id'] == session['user_id'] or 
                is_group_leader(session['user_id'], bug['group_id']))
    
    if not can_edit:
        flash('You can only edit your own bug reports or be a group leader!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=bug['group_id']))
    
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        priority = request.form.get('priority', 'medium')
        
        if not title or not description:
            flash('Title and description are required!', 'error')
        else:
            # Update bug
            conn.execute('''
                UPDATE bugs SET title = ?, description = ?, priority = ?, last_edited = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (title, description, priority, bug_id))
            
            conn.commit()
            conn.close()
            flash('Bug report updated successfully!', 'success')
            return redirect(url_for('group_detail', group_id=bug['group_id']))
    
    conn.close()
    return render_template('edit_bug.html', bug=bug)

@app.route('/approve_bug/<int:bug_id>')
def approve_bug(bug_id):
    """Approve a bug (leader only)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get bug and check if current user is group leader
    bug = conn.execute('''
        SELECT b.*, g.id as group_id
        FROM bugs b
        JOIN groups g ON b.group_id = g.id
        WHERE b.id = ?
    ''', (bug_id,)).fetchone()
    
    if not bug:
        flash('Bug not found!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    if not is_group_leader(session['user_id'], bug['group_id']):
        flash('Only group leaders can approve bugs!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=bug['group_id']))
    
    # Update bug status
    conn.execute(
        'UPDATE bugs SET status = ?, approved_at = CURRENT_TIMESTAMP, approved_by = ? WHERE id = ?',
        ('approved', session['user_id'], bug_id)
    )
    conn.commit()
    conn.close()
    
    flash('Bug approved successfully!', 'success')
    return redirect(url_for('group_detail', group_id=bug['group_id']))

@app.route('/submit_suggestion/<int:group_id>', methods=['POST'])
def submit_suggestion(group_id):
    """Submit a suggestion"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    title = request.form['title'].strip()
    description = request.form['description'].strip()
    
    if not title or not description:
        flash('Title and description are required!', 'error')
        return redirect(url_for('group_detail', group_id=group_id))
    
    conn = get_db_connection()
    
    # Check if user is member of this group
    membership = conn.execute(
        'SELECT * FROM memberships WHERE user_id = ? AND group_id = ?',
        (session['user_id'], group_id)
    ).fetchone()
    
    if not membership:
        flash('You are not a member of this group!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Insert suggestion
    conn.execute('''
        INSERT INTO suggestions (title, description, author_id, group_id)
        VALUES (?, ?, ?, ?)
    ''', (title, description, session['user_id'], group_id))
    
    conn.commit()
    conn.close()
    
    flash('Suggestion submitted successfully!', 'success')
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/approve_suggestion/<int:suggestion_id>')
def approve_suggestion(suggestion_id):
    """Approve a suggestion (leader only)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get suggestion and check if current user is group leader
    suggestion = conn.execute('''
        SELECT s.*, g.id as group_id
        FROM suggestions s
        JOIN groups g ON s.group_id = g.id
        WHERE s.id = ?
    ''', (suggestion_id,)).fetchone()
    
    if not suggestion:
        flash('Suggestion not found!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    if not is_group_leader(session['user_id'], suggestion['group_id']):
        flash('Only group leaders can approve suggestions!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=suggestion['group_id']))
    
    # Update suggestion status
    conn.execute(
        'UPDATE suggestions SET status = ?, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ? WHERE id = ?',
        ('approved', session['user_id'], suggestion_id)
    )
    conn.commit()
    conn.close()
    
    flash('Suggestion approved successfully!', 'success')
    return redirect(url_for('group_detail', group_id=suggestion['group_id']))

@app.route('/reject_suggestion/<int:suggestion_id>')
def reject_suggestion(suggestion_id):
    """Reject a suggestion (leader only)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get suggestion and check if current user is group leader
    suggestion = conn.execute('''
        SELECT s.*, g.id as group_id
        FROM suggestions s
        JOIN groups g ON s.group_id = g.id
        WHERE s.id = ?
    ''', (suggestion_id,)).fetchone()
    
    if not suggestion:
        flash('Suggestion not found!', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    if not is_group_leader(session['user_id'], suggestion['group_id']):
        flash('Only group leaders can reject suggestions!', 'error')
        conn.close()
        return redirect(url_for('group_detail', group_id=suggestion['group_id']))
    
    # Update suggestion status
    conn.execute(
        'UPDATE suggestions SET status = ?, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ? WHERE id = ?',
        ('rejected', session['user_id'], suggestion_id)
    )
    conn.commit()
    conn.close()
    
    flash('Suggestion rejected!', 'success')
    return redirect(url_for('group_detail', group_id=suggestion['group_id']))

@app.route('/api/notifications')
def api_notifications():
    """API endpoint for notification count"""
    if 'user_id' not in session:
        return jsonify({'count': 0})
    
    count = get_unread_notifications_count(session['user_id'])
    return jsonify({'count': count})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)