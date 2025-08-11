import os
import psycopg2
import psycopg2.extras
from datetime import datetime
from flask import (
    Flask, render_template_string, request, redirect, url_for, session,
    flash, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey123')

AVATAR_FOLDER = 'avatars'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

ALLOWED_FULL_NAMES = {
    "Lin Yirou",
    "Sum Wy Lok",
    "Sum Ee Lok",
    "Sum Ann Lok",
    "Lin Hongye"
}

os.makedirs(AVATAR_FOLDER, exist_ok=True)

# ----------------------
# DB connection helpers
# ----------------------

def get_db_connection():
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL env var not set")
    result = urlparse(DATABASE_URL)
    username = result.username
    password = result.password
    database = result.path[1:]
    hostname = result.hostname
    port = result.port or 5432
    conn = psycopg2.connect(
        dbname=database,
        user=username,
        password=password,
        host=hostname,
        port=port
    )
    return conn

def dict_cursor(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            nickname TEXT,
            bio TEXT,
            avatar TEXT
        );
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL
        );
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id SERIAL PRIMARY KEY,
            post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            body TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL
        );
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS chat_messages (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            message TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL
        );
    ''')
    conn.commit()
    c.close()
    conn.close()

# ----------------------
# Helper functions
# ----------------------

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_by_username(username):
    conn = get_db_connection()
    c = dict_cursor(conn)
    c.execute('SELECT * FROM users WHERE username = %s', (username,))
    user = c.fetchone()
    c.close()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_db_connection()
    c = dict_cursor(conn)
    c.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = c.fetchone()
    c.close()
    conn.close()
    return user

def get_post(post_id):
    conn = get_db_connection()
    c = dict_cursor(conn)
    c.execute('''
        SELECT posts.*, users.nickname, users.username, users.avatar FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE posts.id = %s
    ''', (post_id,))
    post = c.fetchone()
    c.close()
    conn.close()
    return post

def get_comments(post_id):
    conn = get_db_connection()
    c = dict_cursor(conn)
    c.execute('''
        SELECT comments.*, users.nickname, users.username, users.avatar FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE post_id = %s ORDER BY timestamp ASC
    ''', (post_id,))
    comments = c.fetchall()
    c.close()
    conn.close()
    return comments

def get_recent_chat(limit=6):
    conn = get_db_connection()
    c = dict_cursor(conn)
    c.execute('''
        SELECT chat_messages.*, users.nickname, users.username, users.avatar FROM chat_messages
        JOIN users ON chat_messages.user_id = users.id
        ORDER BY timestamp DESC LIMIT %s
    ''', (limit,))
    messages = c.fetchall()
    c.close()
    conn.close()
    return reversed(messages)

def get_posts(limit=10):
    conn = get_db_connection()
    c = dict_cursor(conn)
    c.execute('''
        SELECT posts.*, users.nickname, users.username, users.avatar FROM posts
        JOIN users ON posts.user_id = users.id
        ORDER BY timestamp DESC LIMIT %s
    ''', (limit,))
    posts = c.fetchall()
    c.close()
    conn.close()
    return posts

def current_user():
    if 'user_id' in session:
        return get_user_by_id(session['user_id'])
    return None

# ----------------------
# Routes
# ----------------------

@app.route('/')
def home():
    user = current_user()
    posts = get_posts()
    recent_chat = get_recent_chat() if user else None
    return render_template_string(TEMPLATE, page='home', user=user, posts=posts, recent_chat=recent_chat)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm = request.form['confirm']
        nickname = request.form.get('nickname', '').strip()
        bio = request.form.get('bio', '').strip()
        if not username or not password or not confirm:
            flash('Please fill in all required fields.', 'warning')
            return redirect(url_for('register'))
        if password != confirm:
            flash('Passwords do not match.', 'warning')
            return redirect(url_for('register'))
        if get_user_by_username(username):
            flash('Username already taken.', 'warning')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, nickname, bio) VALUES (%s, %s, %s, %s)',
                  (username, hashed_pw, nickname, bio))
        conn.commit()
        c.close()
        conn.close()
        flash('Registered successfully. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template_string(TEMPLATE, page='register', user=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = get_user_by_username(username)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            flash('Logged in successfully.', 'success')
            return redirect(url_for('home'))
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))
    return render_template_string(TEMPLATE, page='login', user=None)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    if request.method == 'POST':
        nickname = request.form.get('nickname', '').strip()
        bio = request.form.get('bio', '').strip()
        avatar_file = request.files.get('avatar')
        avatar_filename = user['avatar']
        if avatar_file and allowed_file(avatar_file.filename):
            filename = secure_filename(avatar_file.filename)
            filename = f"{user['id']}_{filename}"
            avatar_file.save(os.path.join(AVATAR_FOLDER, filename))
            avatar_filename = filename
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('UPDATE users SET nickname=%s, bio=%s, avatar=%s WHERE id=%s',
                  (nickname, bio, avatar_filename, user['id']))
        conn.commit()
        c.close()
        conn.close()
        flash('Profile updated.', 'success')
        return redirect(url_for('profile'))
    return render_template_string(TEMPLATE, page='profile', user=user)

@app.route('/avatars/<filename>')
def avatars(filename):
    return send_from_directory(AVATAR_FOLDER, filename)

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    user = current_user()
    if not user:
        flash('Please login to create a post.', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        subject = request.form.get('subject', '').strip()
        body = request.form.get('body', '').strip()
        if not subject or not body:
            flash('Subject and body are required.', 'warning')
            return redirect(url_for('create_post'))
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('INSERT INTO posts (user_id, subject, body, timestamp) VALUES (%s, %s, %s, %s)',
                  (user['id'], subject, body, datetime.utcnow()))
        conn.commit()
        c.close()
        conn.close()
        flash('Post created.', 'success')
        return redirect(url_for('home'))
    return render_template_string(TEMPLATE, page='create_post', user=user)

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    user = current_user()
    post = get_post(post_id)
    if not post:
        abort(404)
    if request.method == 'POST':
        if not user:
            flash('Login required to comment.', 'warning')
            return redirect(url_for('login'))
        body = request.form.get('body', '').strip()
        if not body:
            flash('Comment cannot be empty.', 'warning')
            return redirect(url_for('view_post', post_id=post_id))
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('INSERT INTO comments (post_id, user_id, body, timestamp) VALUES (%s, %s, %s, %s)',
                  (post_id, user['id'], body, datetime.utcnow()))
        conn.commit()
        c.close()
        conn.close()
        flash('Comment added.', 'success')
        return redirect(url_for('view_post', post_id=post_id))
    comments = get_comments(post_id)
    return render_template_string(TEMPLATE, page='view_post', user=user, post=post, comments=comments)

@app.route('/chat_auth', methods=['GET', 'POST'])
def chat_auth():
    user = current_user()
    if not user:
        flash('Login required.', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        if full_name in ALLOWED_FULL_NAMES:
            session['chat_access'] = True
            flash('Access granted to chat room.', 'success')
            return redirect(url_for('chat'))
        else:
            flash('Access denied. Your full name is not authorized.', 'danger')
    return render_template_string(TEMPLATE, page='chat_auth', user=user)

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    user = current_user()
    if not user:
        flash('Login required.', 'warning')
        return redirect(url_for('login'))
    if not session.get('chat_access'):
        return redirect(url_for('chat_auth'))
    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        if message:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute('INSERT INTO chat_messages (user_id, message, timestamp) VALUES (%s, %s, %s)',
                      (user['id'], message, datetime.utcnow()))
            conn.commit()
            c.close()
            conn.close()
    conn = get_db_connection()
    c = dict_cursor(conn)
    c.execute('''
        SELECT chat_messages.*, users.nickname, users.username, users.avatar FROM chat_messages
        JOIN users ON chat_messages.user_id = users.id
        ORDER BY timestamp ASC
    ''')
    messages = c.fetchall()
    c.close()
    conn.close()
    return render_template_string(TEMPLATE, page='chat', user=user, messages=messages)

# ----------------------
# Template HTML string
# ----------------------

TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Chatterbox by Chickens</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background: linear-gradient(135deg, #ff8c00 0%, #ffd700 100%);
      color: #222;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    .navbar {
      background: #b22222;
      padding: 0.4rem 1rem;
    }
    .navbar-brand {
      color: #fff;
      font-weight: 700;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      font-size: 1.5rem;
      letter-spacing: 2px;
    }
    .nav-link, .btn-outline-light {
      color: #fff !important;
      font-weight: 500;
    }
    .nav-link:hover, .btn-outline-light:hover {
      color: #ffd700 !important;
    }
    .container-main {
      flex-grow: 1;
      margin-top: 1rem;
      margin-bottom: 1rem;
    }
    .fancy {
      background: rgba(255,255,255,0.9);
      border-radius: 15px;
      box-shadow: 0 4px 15px rgba(255,69,0,0.4);
    }
    .avatar {
      width: 48px;
      height: 48px;
      border-radius: 50%;
      object-fit: cover;
      background: #ff4500;
      color: #fff;
      font-weight: 700;
      display: flex;
      justify-content: center;
      align-items: center;
      font-size: 1.5rem;
      user-select: none;
      text-transform: uppercase;
    }
    .list-group-item {
      border-radius: 10px;
      margin-bottom: 0.5rem;
      border: none;
      background: #fff5e6;
      box-shadow: 0 3px 8px rgba(255, 140, 0, 0.3);
    }
    .chat-box {
      max-height: 350px;
      overflow-y: auto;
      background: #fff8dc;
      padding: 0.5rem;
      border-radius: 12px;
      box-shadow: inset 0 0 10px rgba(255, 140, 0, 0.2);
    }
    .message.bubble {
      padding: 0.5rem 0.8rem;
      border-radius: 15px;
      max-width: 75%;
      word-wrap: break-word;
    }
    .message.me {
      background: #ff4500;
      color: white;
      margin-left: auto;
      border-bottom-right-radius: 0;
      animation: slideInRight 0.4s ease forwards;
    }
    .message.other {
      background: #ffd700;
      margin-right: auto;
      border-bottom-left-radius: 0;
      animation: slideInLeft 0.4s ease forwards;
    }
    @keyframes slideInRight {
      0% {opacity: 0; transform: translateX(50px);}
      100% {opacity: 1; transform: translateX(0);}
    }
    @keyframes slideInLeft {
      0% {opacity: 0; transform: translateX(-50px);}
      100% {opacity: 1; transform: translateX(0);}
    }
    .footer {
      background: #b22222;
      color: #ffd700;
      padding: 0.5rem 0;
      text-align: center;
      font-weight: 600;
      user-select: none;
    }
    form textarea, form input {
      border-radius: 10px;
      border: 1px solid #ffa500;
      padding: 0.5rem;
    }
    .btn-danger {
      background: #b22222;
      border: none;
    }
    .btn-danger:hover {
      background: #ff4500;
    }
    a.btn-outline-secondary {
      border-color: #b22222;
      color: #b22222;
    }
    a.btn-outline-secondary:hover {
      background: #b22222;
      color: #ffd700;
    }
    .container a.btn {
      margin-top: 0.3rem;
    }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand">
    <a class="navbar-brand me-auto" href="{{ url_for('home') }}">Chatterbox</a>
    <div class="d-flex">
      {% if user %}
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('profile') }}">Profile</a>
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('create_post') }}">New Post</a>
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('chat_auth') }}">Chat Room</a>
        <a class="btn btn-sm btn-outline-light" href="{{ url_for('logout') }}">Logout</a>
      {% else %}
        <a class="btn btn-sm btn-outline-light me-2" href="{{ url_for('login') }}">Login</a>
        <a class="btn btn-sm btn-outline-light" href="{{ url_for('register') }}">Register</a>
      {% endif %}
    </div>
  </nav>

  <main class="container container-main mt-3 mb-3">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="alert alert-{{category}} alert-dismissible fade show" role="alert">
            {{ message }}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
          </div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    {# HOME PAGE #}
    {% if page == 'home' %}
      <h2>Recent Posts</h2>
      {% if posts %}
        <ul class="list-group">
          {% for post in posts %}
          <li class="list-group-item">
            <a href="{{ url_for('view_post', post_id=post.id) }}"><strong>{{ post.subject }}</strong></a> 
            <small>by {{ post.nickname or post.username }} on {{ post.timestamp.strftime('%Y-%m-%d %H:%M') }}</small>
          </li>
          {% endfor %}
        </ul>
      {% else %}
        <p>No posts yet. Be the first to create one!</p>
      {% endif %}

      {% if recent_chat %}
        <hr>
        <h3>Recent Chat Messages</h3>
        <div class="chat-box mb-3">
          {% for msg in recent_chat %}
            <div class="d-flex align-items-center mb-2">
              {% if msg.avatar %}
                <img src="{{ url_for('avatars', filename=msg.avatar) }}" alt="avatar" class="avatar me-2" style="width:36px;height:36px;">
              {% else %}
                <div class="avatar me-2">{{ (msg.nickname or msg.username)[:1] }}</div>
              {% endif %}
              <div class="message bubble other">{{ msg.message }}</div>
            </div>
          {% endfor %}
        </div>
      {% endif %}
    {% endif %}

    {# REGISTER PAGE #}
    {% if page == 'register' %}
      <h2>Register</h2>
      <form method="POST" class="fancy p-3" novalidate>
        <div class="mb-3">
          <label class="form-label">Username *</label>
          <input type="text" name="username" class="form-control" required maxlength="50">
        </div>
        <div class="mb-3">
          <label class="form-label">Password *</label>
          <input type="password" name="password" class="form-control" required minlength="6">
        </div>
        <div class="mb-3">
          <label class="form-label">Confirm Password *</label>
          <input type="password" name="confirm" class="form-control" required minlength="6">
        </div>
        <div class="mb-3">
          <label class="form-label">Nickname</label>
          <input type="text" name="nickname" class="form-control" maxlength="50">
        </div>
        <div class="mb-3">
          <label class="form-label">Tell us about yourself</label>
          <textarea name="bio" class="form-control" rows="3" maxlength="200"></textarea>
        </div>
        <button type="submit" class="btn btn-danger">Register</button>
      </form>
    {% endif %}

    {# LOGIN PAGE #}
    {% if page == 'login' %}
      <h2>Login</h2>
      <form method="POST" class="fancy p-3" novalidate>
        <div class="mb-3">
          <label class="form-label">Username</label>
          <input type="text" name="username" class="form-control" required maxlength="50">
        </div>
        <div class="mb-3">
          <label class="form-label">Password</label>
          <input type="password" name="password" class="form-control" required minlength="6">
        </div>
        <button type="submit" class="btn btn-danger">Login</button>
      </form>
    {% endif %}

    {# PROFILE PAGE #}
    {% if page == 'profile' %}
      <h2>Profile</h2>
      <form method="POST" enctype="multipart/form-data" class="fancy p-3" novalidate>
        <div class="mb-3 d-flex align-items-center">
          {% if user.avatar %}
            <img src="{{ url_for('avatars', filename=user.avatar) }}" alt="avatar" class="avatar me-3" style="width:80px;height:80px;">
          {% else %}
            <div class="avatar me-3" style="width:80px;height:80px;font-size:2.5rem;">{{ (user.nickname or user.username)[:1] }}</div>
          {% endif %}
          <div>
            <label class="form-label mb-1">Change Avatar</label>
            <input type="file" name="avatar" class="form-control" accept="image/*">
          </div>
        </div>
        <div class="mb-3">
          <label class="form-label">Nickname</label>
          <input type="text" name="nickname" class="form-control" value="{{ user.nickname }}" maxlength="50">
        </div>
        <div class="mb-3">
          <label class="form-label">Tell us about yourself</label>
          <textarea name="bio" class="form-control" rows="3" maxlength="200">{{ user.bio }}</textarea>
        </div>
        <button type="submit" class="btn btn-danger">Save Profile</button>
      </form>
    {% endif %}

    {# CREATE POST PAGE #}
    {% if page == 'create_post' %}
      <h2>Create New Post</h2>
      <form method="POST" class="fancy p-3" novalidate>
        <div class="mb-3">
          <label class="form-label">Subject</label>
          <input type="text" name="subject" class="form-control" maxlength="100" required>
        </div>
        <div class="mb-3">
          <label class="form-label">Body</label>
          <textarea name="body" class="form-control" rows="5" maxlength="2000" required></textarea>
        </div>
        <button type="submit" class="btn btn-danger">Post</button>
      </form>
    {% endif %}

    {# VIEW POST PAGE #}
    {% if page == 'view_post' %}
      <h2>{{ post.subject }}</h2>
      <p class="text-muted">by {{ post.nickname or post.username }} on {{ post.timestamp.strftime('%Y-%m-%d %H:%M') }}</p>
      <div class="fancy p-3 mb-3" style="white-space: pre-wrap;">{{ post.body }}</div>

      <h4>Comments</h4>
      {% if comments %}
        <ul class="list-group mb-3">
          {% for c in comments %}
            <li class="list-group-item d-flex align-items-center">
              {% if c.avatar %}
                <img src="{{ url_for('avatars', filename=c.avatar) }}" alt="avatar" class="avatar me-3" style="width:40px;height:40px;">
              {% else %}
                <div class="avatar me-3">{{ (c.nickname or c.username)[:1] }}</div>
              {% endif %}
              <div>
                <strong>{{ c.nickname or c.username }}</strong> <small class="text-muted">{{ c.timestamp.strftime('%Y-%m-%d %H:%M') }}</small>
                <p style="margin-bottom:0; white-space: pre-wrap;">{{ c.body }}</p>
              </div>
            </li>
          {% endfor %}
        </ul>
      {% else %}
        <p>No comments yet.</p>
      {% endif %}

      {% if user %}
        <form method="POST" class="mb-3">
          <div class="mb-3">
            <textarea name="body" class="form-control" rows="3" maxlength="500" placeholder="Add a comment..." required></textarea>
          </div>
          <button type="submit" class="btn btn-danger">Comment</button>
        </form>
      {% else %}
        <p><a href="{{ url_for('login') }}">Login</a> to comment.</p>
      {% endif %}
    {% endif %}

    {# CHAT AUTH PAGE #}
    {% if page == 'chat_auth' %}
      <h2>Chat Room Access</h2>
      <p>Only authorized full names can enter the chat room.</p>
      <form method="POST" class="fancy p-3" novalidate>
        <div class="mb-3">
          <label class="form-label">Full Name</label>
          <input type="text" name="full_name" class="form-control" required maxlength="100" placeholder="Your full name">
        </div>
        <button type="submit" class="btn btn-danger">Request Access</button>
      </form>
    {% endif %}

    {# CHAT PAGE #}
    {% if page == 'chat' %}
      <h2>Chat Room</h2>
      <div class="chat-box mb-3" id="chatbox">
        {% for msg in messages %}
          <div class="d-flex mb-2 {% if msg.user_id == user.id %}justify-content-end{% else %}justify-content-start{% endif %}">
            {% if msg.user_id != user.id %}
              {% if msg.avatar %}
                <img src="{{ url_for('avatars', filename=msg.avatar) }}" alt="avatar" class="avatar me-2" style="width:40px;height:40px;">
              {% else %}
                <div class="avatar me-2">{{ (msg.nickname or msg.username)[:1] }}</div>
              {% endif %}
            {% endif %}
            <div class="message bubble {% if msg.user_id == user.id %}me{% else %}other{% endif %}">
              {{ msg.message }}
            </div>
            {% if msg.user_id == user.id %}
              {% if user.avatar %}
                <img src="{{ url_for('avatars', filename=user.avatar) }}" alt="avatar" class="avatar ms-2" style="width:40px;height:40px;">
              {% else %}
                <div class="avatar ms-2">{{ (user.nickname or user.username)[:1] }}</div>
              {% endif %}
            {% endif %}
          </div>
        {% endfor %}
      </div>
      <form method="POST" id="chatform">
        <div class="input-group">
          <input type="text" name="message" id="messageInput" class="form-control" placeholder="Type your message..." maxlength="300" autocomplete="off" required>
          <button type="submit" class="btn btn-danger">Send</button>
        </div>
      </form>
    {% endif %}
  </main>

  <footer class="footer mt-auto">
    Chatterbox by Chickens &copy; 2025
  </footer>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    // Scroll chat box to bottom on load and new message
    const chatbox = document.getElementById('chatbox');
    if(chatbox) {
      chatbox.scrollTop = chatbox.scrollHeight;
    }
    // Focus input on chat page load
    const input = document.getElementById('messageInput');
    if(input) input.focus();
    // Auto scroll on form submit
    const form = document.getElementById('chatform');
    if(form) {
      form.addEventListener('submit', () => {
        setTimeout(() => {
          chatbox.scrollTop = chatbox.scrollHeight;
        }, 100);
      });
    }
  </script>
</body>
</html>
"""

# ----------------------
# Init DB before first request
# ----------------------

@app.before_first_request
def before_first_request():
    init_db()

# ----------------------
# Run
# ----------------------

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
