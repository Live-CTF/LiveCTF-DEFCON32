#!/usr/bin/env python3
from flask import Flask, render_template, session, redirect, url_for, request, flash, jsonify
import requests
import sqlite3
import subprocess
from requests.adapters import HTTPAdapter
from rss_parser import RSSParser
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

# In the real world this would be some config but this is easier to deploy
API_KEY = secrets.token_hex(16)
API_SERVER = 'http://localhost:31337'

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
#app.secret_key = 'test'

# In the reql world this would be a real database but this is easier to deploy
def get_db_conn():
    #db_uri = 'file:challenge_database?mode=memory&cache=shared'
    db_uri = '/tmp/db.sqlite3'
    conn = sqlite3.connect(db_uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn

db_conn = get_db_conn()
with db_conn:
    cur = db_conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
                id INTEGER NOT NULL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
                );
                """)
    
    cur.execute("""CREATE TABLE IF NOT EXISTS posts (
                id INTEGER NOT NULL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL
                );
                """)

    admin_password = secrets.token_hex(16)
    debug_password = secrets.token_hex(16)
    cur.execute("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (?, ?, ?);", (1, 'admin', generate_password_hash(admin_password)))
    cur.execute("DELETE FROM posts WHERE user_id = 1;")
    cur.execute("INSERT INTO posts (id, user_id, title, body) VALUES (?, ?, ?, ?);", (1, 1, 'Debug password', f'The debug password is: {debug_password}'))
    cur.close()
db_conn.close()

@app.route("/")
def index():
    return render_template('index.html', session=session)

@app.get("/logout")
def logout():
    del session['user_id']
    del session['username']
    #r = http_request(http_client, 'GET', API_SERVER + '/api/users')
    #r2 = http_request(http_client, 'GET', 'http://localhost:5000@localhost:5001/')
    return redirect(url_for('index'))


@app.get("/register")
def registration_form():
    if 'user_id' in session:
        return redirect(url_for('index'))
    return render_template('register.html', session=session)

@app.post("/register")
def do_register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    error = False
    username = request.form.get('username', None)
    if not username:
        flash('Missing username', 'error')
        error = True
    password = request.form.get('password', None)
    if not password:
        flash('Missing password', 'error')
        error = True
    password2 = request.form.get('password2', None)
    if not password2:
        flash('Missing repeated password', 'error')
        error = True
    if password != password2:
        flash('Passwords don\'t match', 'error')
        error = True
        
    if error:
        return redirect(url_for('registration_form'))

    r = http_request(http_client, 'POST', API_SERVER + '/api/users', {'username': username, 'password': password})
    result = r.json()
    if (error_message := result.get('error', None)) != None:
        flash(error_message, 'error')
        return redirect(url_for('registration_form'))
    
    flash('Successfully registered. Please login')

    return redirect(url_for('login_form'))

@app.get("/login")
def login_form():
    if 'user_id' in session:
        return redirect(url_for('index'))
    return render_template('login.html', session=session)

@app.post("/login")
def do_login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    error = False
    username = request.form.get('username', None)
    if not username:
        flash('Missing username', 'error')
        error = True
    password = request.form.get('password', None)
    if not password:
        flash('Missing password', 'error')
        error = True
    
    if error:
        return redirect(url_for('login_form'))
    
    r = http_request(http_client, 'GET', API_SERVER + f'/api/usernames/{username}')
    result = r.json()
    if (error_message := result.get('error', None)) != None:
        flash(error_message, 'error')
        return redirect(url_for('login_form'))
    
    user = result['user']
    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        return redirect(url_for('index'))    
    
    flash('Username or password invalid.', 'error')
    return redirect(url_for('login_form'))    


@app.get("/import")
def import_rss_form():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('import.html', session=session)

@app.post("/import")
def do_rss_import():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    error = False
    url = request.form.get('url', None)
    if not url:
        flash('Missing url', 'error')
        error = True
    
    if error:
        return redirect(url_for('import_rss_form'))

    try:
        r = http_request(http_client, 'GET', url)
    except:
        flash('Failed to fetch RSS feed', 'error')
        return redirect(url_for('import_rss_form'))
    
    try:
        rss = RSSParser.parse(r.text)
    except:
        flash('Invalid RSS feed', 'error')
        return redirect(url_for('import_rss_form'))
    
    for item in rss.channel.items:
        r = http_request(http_client, 'POST', API_SERVER + '/api/posts', {'user_id': session['user_id'], 'title': str(item.title.content), 'body': str(item.description.content)})
        result = r.json()
        if (error_message := result.get('error', None)) != None:
            flash(error_message, 'error')
            return redirect(url_for('import_rss_form'))

    return redirect(url_for('posts_list'))

@app.get("/posts")
def posts_list():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    r = http_request(http_client, 'GET', API_SERVER + f'/api/users/{session["user_id"]}/posts')
    result = r.json()
    if (error_message := result.get('error', None)) != None:
        flash(error_message, 'error')
        return redirect(url_for('import_rss_form'))

    return render_template('posts.html', session=session, posts=result['posts'])

@app.get("/posts/<int:post_id>")
def post_view(post_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    r = http_request(http_client, 'GET', API_SERVER + f'/api/posts/{post_id}')
    result = r.json()
    if (error_message := result.get('error', None)) != None:
        flash(error_message, 'error')
        return redirect(url_for('posts_list'))

    post = result['post']
    if post['user_id'] != session['user_id']:
        flash('You can only view your own posts', 'error')
        return redirect(url_for('posts_list'))

    return render_template('post.html', session=session, post=post)

@app.get("/debug")
def debug_form():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    if session['user_id'] != 1:
        flash('Debug only allowed for admin', 'error')
        return redirect(url_for('index'))

    return render_template('debug.html', session=session)

@app.post("/debug")
def do_debug():
    error = False
    debug_password_input = request.form.get('debug_password', None)
    if not debug_password:
        flash('Missing debug_password', 'error')
        error = True
    command = request.form.get('command', None)
    if not command:
        flash('Missing command', 'error')
        error = True
        
    if debug_password_input != debug_password:
        flash('Incorrect debug password', 'error')
        error = True
        
    if error:
        return redirect(url_for('debug_form'))
    
    output = subprocess.check_output(command, shell=True).decode()

    return render_template('debug.html', session=session, output=output)

# API: Users
@app.get("/api/users")
def api_list_users():
    if request.headers.get('x-API-KEY', None) != API_KEY:
        return jsonify({'error': 'Invalid API key'}), 403
    
    db_conn = get_db_conn()
    try:
        with db_conn:
            cur = db_conn.cursor()
            cur.execute('SELECT * FROM users;')
            users = cur.fetchall()
            cur.close()
    except sqlite3.Error as e:
        return jsonify({'error': f'failed to get users: {e}'}), 500
    finally:
        db_conn.close()

    return jsonify({'error': None, 'users': [dict(x) for x in users]})


@app.get("/api/usernames/<string:username>")
def api_get_username(username):
    if request.headers.get('x-API-KEY', None) != API_KEY:
        return jsonify({'error': 'Invalid API key'}), 403
    
    db_conn = get_db_conn()
    try:
        with db_conn:
            cur = db_conn.cursor()
            cur.execute('SELECT * FROM users WHERE username = ?;', (username,))
            user = cur.fetchone()
            cur.close()
    except sqlite3.Error as e:
        return jsonify({'error': f'failed to get user: {e}'}), 500
    finally:
        db_conn.close()

    return jsonify({'error': None, 'user': dict(user) if user else None})


@app.get("/api/users/<int:user_id>")
def api_get_user(user_id):
    if request.headers.get('x-API-KEY', None) != API_KEY:
        return jsonify({'error': 'Invalid API key'}), 403
    
    db_conn = get_db_conn()
    try:
        with db_conn:
            cur = db_conn.cursor()
            cur.execute('SELECT * FROM users WHERE id = ?;', (user_id,))
            user = cur.fetchone()
            cur.close()
    except sqlite3.Error as e:
        return jsonify({'error': f'failed to get user: {e}'}), 500
    finally:
        db_conn.close()

    if not user:
        return jsonify({'error': 'user not found'}), 404
    
    return jsonify({'error': None, 'user': dict(user)})

@app.get("/api/users/<int:user_id>/posts")
def api_get_user_posts(user_id):
    if request.headers.get('x-API-KEY', None) != API_KEY:
        return jsonify({'error': 'Invalid API key'}), 403
    
    db_conn = get_db_conn()
    try:
        with db_conn:
            cur = db_conn.cursor()
            cur.execute('SELECT * FROM posts WHERE user_id = ?;', (user_id,))
            posts = cur.fetchall()
            cur.close()
    except sqlite3.Error as e:
        return jsonify({'error': f'failed to get users: {e}'}), 500
    finally:
        db_conn.close()

    return jsonify({'error': None, 'posts': [dict(x) for x in posts]})

@app.put("/api/users/<int:user_id>")
def api_update_user(user_id):
    if request.headers.get('x-API-KEY', None) != API_KEY:
        return jsonify({'error': 'Invalid API key'}), 403
    
    raise NotImplemented('Not implemented')

@app.post("/api/users")
def api_create_user():
    if request.headers.get('x-API-KEY', None) != API_KEY:
        return jsonify({'error': 'Invalid API key'}), 403
    username = request.json['username']
    password = request.json['password']
    password_hash = generate_password_hash(password)
    
    db_conn = get_db_conn()
    try:
        with db_conn:
            cur = db_conn.cursor()
            cur.execute('INSERT INTO users (username, password_hash) VALUES (?, ?);', (username, password_hash))
            cur.close()
    except sqlite3.Error as e:
        return jsonify({'error': f'failed to create user: {e}'})
    finally:
        db_conn.close()

    return jsonify({'error': None})

# API: Posts
@app.get("/api/posts")
def api_list_posts():
    if request.headers.get('x-API-KEY', None) != API_KEY:
        return jsonify({'error': 'Invalid API key'}), 403
    
    db_conn = get_db_conn()
    try:
        with db_conn:
            cur = db_conn.cursor()
            cur.execute('SELECT * FROM posts;')
            posts = cur.fetchall()
            cur.close()
    except sqlite3.Error as e:
        return jsonify({'error': f'failed to get users: {e}'}), 500
    finally:
        db_conn.close()

    return jsonify({'error': None, 'posts': [dict(x) for x in posts]})

@app.get("/api/posts/<int:post_id>")
def api_get_post(post_id):
    if request.headers.get('x-API-KEY', None) != API_KEY:
        return jsonify({'error': 'Invalid API key'}), 403
    
    db_conn = get_db_conn()
    try:
        with db_conn:
            cur = db_conn.cursor()
            cur.execute('SELECT * FROM posts WHERE id = ?;', (post_id,))
            post = cur.fetchone()
            cur.close()
    except sqlite3.Error as e:
        return jsonify({'error': f'failed to get post: {e}'}), 500
    finally:
        db_conn.close()

    if not post:
        return jsonify({'error': 'post not found'}), 404
    
    return jsonify({'error': None, 'post': dict(post)})

@app.put("/api/posts/<int:post_id>")
def api_update_post(post_id):
    if request.headers.get('x-API-KEY', None) != API_KEY:
        return jsonify({'error': 'Invalid API key'}), 403
    raise NotImplemented('Not implemented')

@app.post("/api/posts")
def api_create_post():
    if request.headers.get('x-API-KEY', None) != API_KEY:
        return jsonify({'error': 'Invalid API key'}), 403
    
    user_id = request.json['user_id']
    title = request.json['title']
    body = request.json['body']
    
    db_conn = get_db_conn()
    try:
        with db_conn:
            cur = db_conn.cursor()
            cur.execute('INSERT INTO posts (user_id, title, body) VALUES (?, ?, ?);', (user_id, title, body))
            cur.close()
    except sqlite3.Error as e:
        return jsonify({'error': f'failed to create post: {e}'})
    finally:
        db_conn.close()

    return jsonify({'error': None})

class ApiAdapter(HTTPAdapter):
    def add_headers(self, request, **kwargs):
        request.headers['X-API-KEY'] = API_KEY

def init_http_client():
    s = requests.Session()
    s.mount(API_SERVER, ApiAdapter())
    return s

def http_request(session, method, url, json=None):
    return session.request(method, url, json=json)

http_client = init_http_client()
