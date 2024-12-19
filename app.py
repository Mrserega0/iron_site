import os
from flask import Flask, render_template, url_for, request, session
import sqlite3
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import redirect, secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.secret_key = "your_secret_key"
login_manager = LoginManager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

app.app_context().push()

# Модель аккаунта
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String)
    role = db.Column(db.String, default='user')
    age = db.Column(db.Integer)

    # Метод для получения пользователя по id
    def get(self, user_id):
        user = self.query.filter_by(id=user_id).first()
        return user

    # Методы для работы с flask-login
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

# Модель новых страниц
class Page(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    content = db.Column(db.Text, nullable=False)
    content_title = db.Column(db.Text, nullable=False)
    image_path = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    age = db.Column(db.Integer)

# Загрузка пользователя по для flask-login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Маршрут для регистрации пользователей
@app.route("/reg", methods=['POST', 'GET']) 
def reg_menu():
    if request.method == 'POST':  # Если отправлена форма регистрации
        email = request.form['login']  # Получаем email из формы
        if User.query.filter_by(email=email).first():  # Проверяем, существует ли пользователь
            regis = "Пользователь с таким email уже существует."
            return render_template("register.html", regis=regis)
        
        hash = generate_password_hash(request.form['password'])  # Хэшируем пароль
        user = User(email=email, password=hash)  # Создаем нового пользователя
        db.session.add(user)  # Добавляем пользователя в базу данных
        db.session.commit()  # Сохраняем изменения
        login_user(user)  # Авторизуем пользователя
        return redirect('/')  # Перенаправляем на главную страницу
    else:
        return render_template('register.html')  # Отображаем форму регистрации

# Маршрут для входа пользователей
@app.route("/login", methods=['POST', 'GET'])
def login_menu():
    if request.method == 'POST':  # Если отправлена форма входа
        password = request.form['password']  # Получаем пароль из формы
        email = request.form['login']  # Получаем email из формы
        user = User.query.filter_by(email=email).first()  # Ищем пользователя по email
        if user and check_password_hash(user.password, password):  # Проверяем пароль
            login_user(user)  # Авторизуем пользователя
            return redirect('/')  # Перенаправляем на главную страницу
        else:
            log = "Пользователь с таким email не существует."
            return render_template("login.html", log=log)
    else:
        return render_template('login.html', cur_user=current_user)  # Отображаем форму входа

# Маршрут для добавления новой страницы (доступно только администраторам)
@app.route("/admin/add_page", methods=["GET", "POST"])
@login_required
def add_page():
    if current_user.role != "admin":
        return "Доступ запрещен", 403

    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        content_title = request.form["content_title"] 
        file = request.files.get("image")
        image_path = None

        if file:
            filename = secure_filename(file.filename)
            image_path = os.path.join("static/images", filename)
            file.save(os.path.join(app.root_path, image_path))

        new_page = Page(title=title, content=content, image_path=image_path,content_title=content_title)
        db.session.add(new_page)
        db.session.commit()
        return redirect("/")

    return render_template("add_page.html")

# Маршрут для просмотра страницы
@app.route("/page/<int:page_id>", methods=["GET", "POST"])
def view_page(page_id):
    page = Page.query.get_or_404(page_id)  # Получаем страницу по ID или возвращаем 404

    if request.method == "POST":  # Если отправлена форма редактирования страницы
        if not current_user.is_authenticated or current_user.role != "admin":  # Проверяем права доступа
            return "Доступ запрещен", 403

        page.title = request.form["title"]
        page.content = request.form["content"]
        page.content_title = request.form["content_title"] 
        file = request.files.get("image")

        if file:
            filename = secure_filename(file.filename)  # Безопасное имя файла
            image_path = os.path.join("static/images", filename).replace("\\", "/")  # Преобразование пути
            file.save(os.path.join(app.root_path, image_path))  # Сохранение файла


        db.session.commit()  # Сохраняем изменения в базе данных
        return redirect(url_for('view_page', page_id=page_id))  # Перенаправляем на страницу

    is_admin = current_user.is_authenticated and current_user.role == "admin"  # Проверяем, является ли пользователь администратором
    return render_template("view_page.html", page=page, is_admin=is_admin)  # Отображаем страницу

# Проверка, является ли пользователь администратором
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

@app.context_processor
def inject_pages():
    pages = Page.query.all()  # Получить все страницы
    return dict(pages=pages)

# Выход из аккаунта
@app.route('/logout') 
def logout():
    logout_user()  # Выполняем выход пользователя
    return redirect(url_for('index'))  # Перенаправляем на главную страницу

if __name__ == '__main__':
    app.run(debug=True)
