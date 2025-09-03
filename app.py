from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import os
from werkzeug.utils import secure_filename
import sqlite3
from datetime import datetime
import json
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt'}

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Custom Jinja2 filters
@app.template_filter('from_json')
def from_json_filter(value):
    """Convert JSON string to Python object"""
    if value:
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return []
    return []

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Get current user information"""
    if 'user_id' not in session:
        return None
    
    conn = sqlite3.connect('resume_analyzer.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return {
            'id': user_data[0],
            'username': user_data[1],
            'email': user_data[2],
            'full_name': user_data[4],
            'role': user_data[5],
            'created_date': user_data[6],
            'last_login': user_data[7]
        }
    return None

def init_db():
    """Initialize the database"""
    conn = sqlite3.connect('resume_analyzer.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            role TEXT DEFAULT 'user',
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Create resumes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS resumes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            extracted_text TEXT,
            skills TEXT,
            experience TEXT,
            education TEXT,
            contact_info TEXT,
            overall_score REAL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create job_descriptions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS job_descriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            required_skills TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create matches table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            resume_id INTEGER,
            job_id INTEGER,
            match_score REAL,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (resume_id) REFERENCES resumes (id),
            FOREIGN KEY (job_id) REFERENCES job_descriptions (id)
        )
    ''')
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        if request.is_json or request.content_type == 'application/json':
            # Handle AJAX request
            data = request.get_json()
            username_or_email = data.get('username_or_email')
            password = data.get('password')
            remember_me = data.get('remember_me', False)
        else:
            # Handle form request
            username_or_email = request.form.get('username_or_email')
            password = request.form.get('password')
            remember_me = request.form.get('remember_me') == 'on'
        
        if not username_or_email or not password:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Username/email and password are required'})
            flash('Username/email and password are required')
            return redirect(url_for('login'))
        
        # Check if user exists
        conn = sqlite3.connect('resume_analyzer.db')
        cursor = conn.cursor()
        
        # Check by username or email
        cursor.execute('''
            SELECT id, username, email, password_hash, full_name, role 
            FROM users 
            WHERE username = ? OR email = ?
        ''', (username_or_email, username_or_email))
        
        user = cursor.fetchone()
        
        if user and check_password_hash(user[3], password):
            # Update last login
            cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
            conn.commit()
            
            # Set session
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['email'] = user[2]
            session['full_name'] = user[4]
            session['role'] = user[5]
            
            # Set session timeout if remember me is not checked
            if not remember_me:
                session.permanent = False
            else:
                session.permanent = True
                from datetime import timedelta
                app.permanent_session_lifetime = timedelta(days=30)
            
            conn.close()
            
            if request.is_json:
                return jsonify({
                    'success': True, 
                    'message': 'Login successful!',
                    'redirect': url_for('index')
                })
            
            flash('Login successful!')
            return redirect(url_for('index'))
        else:
            conn.close()
            if request.is_json:
                return jsonify({'success': False, 'message': 'Invalid username/email or password'})
            flash('Invalid username/email or password')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        if request.is_json or request.content_type == 'application/json':
            # Handle AJAX request
            data = request.get_json()
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            full_name = data.get('full_name')
        else:
            # Handle form request
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            full_name = request.form.get('full_name')
        
        # Validation
        if not all([username, email, password]):
            if request.is_json:
                return jsonify({'success': False, 'message': 'All required fields must be filled'})
            flash('All required fields must be filled')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Password must be at least 6 characters long'})
            flash('Password must be at least 6 characters long')
            return redirect(url_for('register'))
        
        # Check if user already exists
        conn = sqlite3.connect('resume_analyzer.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            if request.is_json:
                return jsonify({'success': False, 'message': 'Username or email already exists'})
            flash('Username or email already exists')
            return redirect(url_for('register'))
        
        # Create new user
        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, full_name)
            VALUES (?, ?, ?, ?)
        ''', (username, email, password_hash, full_name))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Auto-login after registration
        session['user_id'] = user_id
        session['username'] = username
        session['email'] = email
        session['full_name'] = full_name
        session['role'] = 'user'
        
        if request.is_json:
            return jsonify({
                'success': True, 
                'message': 'Account created successfully!',
                'redirect': url_for('index')
            })
        
        flash('Account created successfully!')
        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out successfully')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    user = get_current_user()
    return render_template('profile.html', user=user)

@app.route('/upload', methods=['GET', 'POST'])
def upload_resume():
    """Upload resume page"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to avoid filename conflicts
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Process the resume
            from resume_processor import process_resume
            result = process_resume(filepath, file.filename)
            
            if result['success']:
                flash('Resume uploaded and processed successfully!')
                return redirect(url_for('view_resume', resume_id=result['resume_id']))
            else:
                flash(f'Error processing resume: {result["error"]}')
                return redirect(request.url)
        else:
            flash('Invalid file type. Please upload PDF, DOC, DOCX, or TXT files.')
            return redirect(request.url)
    
    return render_template('upload.html')

@app.route('/resumes')
def list_resumes():
    """List all uploaded resumes"""
    conn = sqlite3.connect('resume_analyzer.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, original_filename, upload_date, overall_score 
        FROM resumes 
        ORDER BY upload_date DESC
    ''')
    resumes = cursor.fetchall()
    conn.close()
    
    return render_template('resumes.html', resumes=resumes)

@app.route('/resume/<int:resume_id>')
def view_resume(resume_id):
    """View individual resume details"""
    conn = sqlite3.connect('resume_analyzer.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM resumes WHERE id = ?', (resume_id,))
    resume = cursor.fetchone()
    conn.close()
    
    if not resume:
        flash('Resume not found')
        return redirect(url_for('list_resumes'))
    
    # Parse JSON fields
    resume_data = {
        'id': resume[0],
        'filename': resume[1],
        'original_filename': resume[2],
        'upload_date': resume[3],
        'extracted_text': resume[4],
        'skills': json.loads(resume[5]) if resume[5] else [],
        'experience': json.loads(resume[6]) if resume[6] else [],
        'education': json.loads(resume[7]) if resume[7] else [],
        'contact_info': json.loads(resume[8]) if resume[8] else {},
        'overall_score': resume[9]
    }
    
    return render_template('resume_detail.html', resume=resume_data)

@app.route('/jobs', methods=['GET', 'POST'])
def manage_jobs():
    """Manage job descriptions"""
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        
        if title and description:
            # Process job description to extract required skills
            from resume_processor import extract_skills_from_text
            required_skills = extract_skills_from_text(description)
            
            conn = sqlite3.connect('resume_analyzer.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO job_descriptions (title, description, required_skills)
                VALUES (?, ?, ?)
            ''', (title, description, json.dumps(required_skills)))
            conn.commit()
            conn.close()
            
            flash('Job description added successfully!')
            return redirect(url_for('manage_jobs'))
        else:
            flash('Please fill in all fields')
    
    # Get all job descriptions
    conn = sqlite3.connect('resume_analyzer.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM job_descriptions ORDER BY created_date DESC')
    jobs = cursor.fetchall()
    conn.close()
    
    return render_template('jobs.html', jobs=jobs)

@app.route('/match/<int:resume_id>/<int:job_id>')
def match_resume_job(resume_id, job_id):
    """Calculate match between resume and job"""
    from resume_processor import calculate_match_score
    
    conn = sqlite3.connect('resume_analyzer.db')
    cursor = conn.cursor()
    
    # Get resume data
    cursor.execute('SELECT skills FROM resumes WHERE id = ?', (resume_id,))
    resume_data = cursor.fetchone()
    
    # Get job data
    cursor.execute('SELECT required_skills FROM job_descriptions WHERE id = ?', (job_id,))
    job_data = cursor.fetchone()
    
    if resume_data and job_data:
        resume_skills = json.loads(resume_data[0]) if resume_data[0] else []
        job_skills = json.loads(job_data[0]) if job_data[0] else []
        
        match_score = calculate_match_score(resume_skills, job_skills)
        
        # Save match result
        cursor.execute('''
            INSERT OR REPLACE INTO matches (resume_id, job_id, match_score)
            VALUES (?, ?, ?)
        ''', (resume_id, job_id, match_score))
        conn.commit()
        
        result = {'match_score': match_score, 'success': True}
    else:
        result = {'success': False, 'error': 'Resume or job not found'}
    
    conn.close()
    return jsonify(result)

@app.route('/analytics')
def analytics():
    """Analytics dashboard"""
    conn = sqlite3.connect('resume_analyzer.db')
    cursor = conn.cursor()
    
    # Get statistics
    cursor.execute('SELECT COUNT(*) FROM resumes')
    total_resumes = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM job_descriptions')
    total_jobs = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM matches')
    total_matches = cursor.fetchone()[0]
    
    cursor.execute('SELECT AVG(overall_score) FROM resumes WHERE overall_score > 0')
    avg_score = cursor.fetchone()[0] or 0
    
    # Get top skills
    cursor.execute('SELECT skills FROM resumes WHERE skills IS NOT NULL')
    all_skills = []
    for row in cursor.fetchall():
        try:
            skills = json.loads(row[0])
            all_skills.extend(skills)
        except (json.JSONDecodeError, TypeError):
            continue
    
    # Count skill frequency
    from collections import Counter
    skill_counts = Counter(all_skills)
    top_skills = skill_counts.most_common(10)
    
    # Get timeline data for the last 30 days
    cursor.execute('''
        SELECT DATE(upload_date) as date, COUNT(*) as count
        FROM resumes 
        WHERE upload_date >= date('now', '-30 days')
        GROUP BY DATE(upload_date)
        ORDER BY date
    ''')
    resume_timeline = cursor.fetchall()
    
    cursor.execute('''
        SELECT DATE(created_date) as date, COUNT(*) as count
        FROM job_descriptions 
        WHERE created_date >= date('now', '-30 days')
        GROUP BY DATE(created_date)
        ORDER BY date
    ''')
    job_timeline = cursor.fetchall()
    
    # Get recent activity (last 20 activities)
    recent_activities = []
    
    # Recent resume uploads
    cursor.execute('''
        SELECT 'resume_upload' as type, original_filename as title, upload_date as date
        FROM resumes 
        ORDER BY upload_date DESC 
        LIMIT 10
    ''')
    for row in cursor.fetchall():
        recent_activities.append({
            'type': row[0],
            'title': row[1],
            'date': row[2],
            'icon': 'fas fa-file-alt',
            'color': 'primary',
            'description': 'New Resume Uploaded'
        })
    
    # Recent job postings
    cursor.execute('''
        SELECT 'job_post' as type, title, created_date as date
        FROM job_descriptions 
        ORDER BY created_date DESC 
        LIMIT 10
    ''')
    for row in cursor.fetchall():
        recent_activities.append({
            'type': row[0],
            'title': row[1],
            'date': row[2],
            'icon': 'fas fa-briefcase',
            'color': 'info',
            'description': 'New Job Posted'
        })
    
    # Sort all activities by date
    recent_activities.sort(key=lambda x: x['date'], reverse=True)
    recent_activities = recent_activities[:15]  # Keep only the 15 most recent
    
    # Format timeline data for Chart.js
    timeline_data = get_timeline_data(resume_timeline, job_timeline)
    
    conn.close()
    
    stats = {
        'total_resumes': total_resumes,
        'total_jobs': total_jobs,
        'total_matches': total_matches,
        'avg_score': round(avg_score, 2),
        'top_skills': top_skills,
        'timeline_data': timeline_data,
        'recent_activities': recent_activities
    }
    
    return render_template('analytics.html', stats=stats)

@app.route('/api/analytics/timeline/<period>')
def get_timeline_api(period):
    """API endpoint to get timeline data for different periods"""
    conn = sqlite3.connect('resume_analyzer.db')
    cursor = conn.cursor()
    
    # Determine the date range based on period
    if period == '7d':
        days = 7
    elif period == '30d':
        days = 30
    elif period == '90d':
        days = 90
    else:
        days = 30
    
    # Get timeline data
    cursor.execute(f'''
        SELECT DATE(upload_date) as date, COUNT(*) as count
        FROM resumes 
        WHERE upload_date >= date('now', '-{days} days')
        GROUP BY DATE(upload_date)
        ORDER BY date
    ''')
    resume_timeline = cursor.fetchall()
    
    cursor.execute(f'''
        SELECT DATE(created_date) as date, COUNT(*) as count
        FROM job_descriptions 
        WHERE created_date >= date('now', '-{days} days')
        GROUP BY DATE(created_date)
        ORDER BY date
    ''')
    job_timeline = cursor.fetchall()
    
    conn.close()
    
    timeline_data = get_timeline_data_for_period(resume_timeline, job_timeline, days)
    return jsonify(timeline_data)

@app.route('/api/analytics/recent-activity')
def get_recent_activity_api():
    """API endpoint to get recent activity"""
    conn = sqlite3.connect('resume_analyzer.db')
    cursor = conn.cursor()
    
    recent_activities = []
    
    # Recent resume uploads
    cursor.execute('''
        SELECT 'resume_upload' as type, original_filename as title, upload_date as date
        FROM resumes 
        ORDER BY upload_date DESC 
        LIMIT 10
    ''')
    for row in cursor.fetchall():
        recent_activities.append({
            'type': row[0],
            'title': row[1],
            'date': row[2],
            'icon': 'fas fa-file-alt',
            'color': 'primary',
            'description': 'New Resume Uploaded'
        })
    
    # Recent job postings
    cursor.execute('''
        SELECT 'job_post' as type, title, created_date as date
        FROM job_descriptions 
        ORDER BY created_date DESC 
        LIMIT 10
    ''')
    for row in cursor.fetchall():
        recent_activities.append({
            'type': row[0],
            'title': row[1],
            'date': row[2],
            'icon': 'fas fa-briefcase',
            'color': 'info',
            'description': 'New Job Posted'
        })
    
    # Sort all activities by date
    recent_activities.sort(key=lambda x: x['date'], reverse=True)
    recent_activities = recent_activities[:15]
    
    conn.close()
    return jsonify(recent_activities)

# API endpoints for real-time functionality
@app.route('/api/check-username', methods=['POST'])
def check_username():
    """Check if username is available"""
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({'available': False})
    
    conn = sqlite3.connect('resume_analyzer.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    existing_user = cursor.fetchone()
    conn.close()
    
    return jsonify({'available': existing_user is None})

@app.route('/api/check-email', methods=['POST'])
def check_email():
    """Check if email is available"""
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({'available': False})
    
    conn = sqlite3.connect('resume_analyzer.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    existing_user = cursor.fetchone()
    conn.close()
    
    return jsonify({'available': existing_user is None})

@app.route('/api/create-demo-accounts', methods=['POST'])
def create_demo_accounts():
    """Create demo accounts for testing"""
    conn = sqlite3.connect('resume_analyzer.db')
    cursor = conn.cursor()
    
    demo_accounts = [
        ('demo', 'demo@example.com', 'demo123', 'Demo User'),
        ('admin', 'admin@example.com', 'admin123', 'Admin User')
    ]
    
    for username, email, password, full_name in demo_accounts:
        # Check if account already exists
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if not cursor.fetchone():
            password_hash = generate_password_hash(password)
            role = 'admin' if username == 'admin' else 'user'
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, full_name, role)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, email, password_hash, full_name, role))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Demo accounts created'})

def get_timeline_data(resume_timeline, job_timeline):
    """Format timeline data for Chart.js"""
    from datetime import datetime, timedelta
    
    # Create a dictionary for easy lookup
    resume_dict = {row[0]: row[1] for row in resume_timeline}
    job_dict = {row[0]: row[1] for row in job_timeline}
    
    # Generate last 30 days
    timeline_labels = []
    resume_counts = []
    job_counts = []
    
    for i in range(29, -1, -1):  # Last 30 days
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        timeline_labels.append(date)
        resume_counts.append(resume_dict.get(date, 0))
        job_counts.append(job_dict.get(date, 0))
    
    return {
        'labels': timeline_labels,
        'resume_data': resume_counts,
        'job_data': job_counts
    }

def get_timeline_data_for_period(resume_timeline, job_timeline, days):
    """Format timeline data for Chart.js for specific period"""
    from datetime import datetime, timedelta
    
    # Create a dictionary for easy lookup
    resume_dict = {row[0]: row[1] for row in resume_timeline}
    job_dict = {row[0]: row[1] for row in job_timeline}
    
    # Generate labels for the specified period
    timeline_labels = []
    resume_counts = []
    job_counts = []
    
    for i in range(days - 1, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        timeline_labels.append(date)
        resume_counts.append(resume_dict.get(date, 0))
        job_counts.append(job_dict.get(date, 0))
    
    return {
        'labels': timeline_labels,
        'resume_data': resume_counts,
        'job_data': job_counts
    }

if __name__ == '__main__':
    init_db()
    app.run(debug=True)