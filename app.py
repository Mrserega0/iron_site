import os
from flask import Flask, render_template, url_for, request, session
import sqlite3
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import redirect,secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, login_user, login_required, current_user,logout_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.secret_key = "your_secret_key"
login_manager = LoginManager(app)
db = SQLAlchemy(app)
app.app_context().push()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String)
    role = db.Column(db.String, default='user')

    def get(self, user_id):
        user = self.query.filter_by(id=user_id).first()
        return user

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id
    
class Page(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_path = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/reg", methods=['POST', 'GET']) 
def reg_menu():
    if request.method == 'POST':
        email = request.form['login']
        if User.query.filter_by(email=email).first():
            return 'Пользователь с таким email уже существует'
        
        hash = generate_password_hash(request.form['password'])
        user = User(email=email, password=hash)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect('/')
    else:
        return render_template('register.html')

@app.route("/login", methods=['POST', 'GET'])
def login_menu():
    if request.method == 'POST':
        password = request.form['password']
        email = request.form['login']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/')
        else:
            return redirect('/login')
    else:
        return render_template('login.html', cur_user = current_user)
    
@app.route("/admin/add_page", methods=["GET", "POST"])
@login_required
def add_page():
    if current_user.role != "admin":
        return "Доступ запрещен", 403

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        file = request.files.get("image")
        image_path = None
        
        if file:
            filename = secure_filename(file.filename)
            image_path = os.path.join("static/images", filename)
            file.save(image_path)

        new_page = Page(title=title, content=content, image_path=image_path)
        db.session.add(new_page)
        db.session.commit()
        return redirect("/")

    return render_template("add_page.html")

@app.route("/page/<int:page_id>", methods=["GET", "POST"])
@login_required
def view_page(page_id):
    page = Page.query.get_or_404(page_id)

    if request.method == "POST" and current_user.role == "admin":
        page.title = request.form["title"]
        page.content = request.form["content"]
        file = request.files.get("image")

        if file:
            filename = secure_filename(file.filename)
            image_path = os.path.join("static/images", filename)
            file.save(image_path)
            page.image_path = image_path

        db.session.commit()
        return redirect(url_for('view_page', page_id=page_id))

    return render_template("view_page.html", page=page, is_admin=(current_user.role == "admin"))
    
def is_admin():
    return session.get("role") == "admin"

# Главная страница
@app.route("/")
def index():
    pages = Page.query.all()
    return render_template("index.html", cur_user=current_user, pages=pages)

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

# Выход
@app.route('/logout') 
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

