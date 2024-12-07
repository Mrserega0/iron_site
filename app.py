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
    
class Products(db.Model):
  id = db.Column(db.Integer, primary_key = True)
  name = db.Column(db.String, nullable = False)
  file_path = db.Column(db.String)
  user_id = db.Column(db.Integer)
  discription = db.Column(db.String)
  price = db.Column(db.Integer)

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
    
@app.route("/admin", methods = ['POST', 'GET'])
@login_required
def add():
  if request.method == 'GET':
    print('get')
    return render_template('newAdd.html')
  else:
    name = request.form['name']
    price = request.form['price']
    discription = request.form['discription']
    file = request.files['file_img']
    filename = secure_filename(file.filename)

    product = Products(name=name, price = int(price),discription = discription, user_id = str(current_user.id), file_path = 'a' + str(current_user.id) + filename)
    db.session.add(product)
    db.session.commit()
    print('is commit')
    
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'a' + str(current_user.id)+ filename))
    return redirect ('/')
    
def is_admin():
    return session.get("role") == "admin"

# Главная страница
@app.route("/")
def index():
    products = Products.query.all()
    return render_template("index.html",products = products, cur_user = current_user)

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

