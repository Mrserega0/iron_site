# from flask import Flask, render_template

# app = Flask(__name__)

# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/about')
# def about():
#     return render_template('about.html')

# @app.route('/contact')
# def contact():
#     return render_template('contact.html')

# @app.route('/service')
# def service():
#     return render_template('service.html')

# @app.route('/team')
# def team():
#     return render_template('team.html')

# if __name__ == '__main__':
#     app.run(debug=True)























from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "d2f4c5f9f218cb11adf68ab68f1b9cde"

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

# Главная страница
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/service')
def service():
    return render_template('service.html')

@app.route('/team')
def team():
    return render_template('team.html')

# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            flash("Вы успешно зарегистрировались!", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Имя пользователя уже занято!", "danger")
    return render_template('register.html')

# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        
        if result and check_password_hash(result[0], password):
            session['username'] = username
            flash("Вы успешно вошли в систему!", "success")
            return redirect(url_for('index'))
        else:
            flash("Неправильное имя пользователя или пароль!", "danger")
    return render_template('login.html')

# Выход
@app.route('/logout') 
def logout():
    session.pop('username', None)
    flash("Вы вышли из системы.", "info")
    return redirect(url_for('login'))

if __name__ == '_main_':
    init_db()
    app.run(debug=True)