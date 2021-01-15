from flask import Flask, render_template, request, redirect, flash, url_for
from flask_login import UserMixin, login_user, logout_user, LoginManager, login_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
import os

app = Flask(__name__)
app.secret_key = 'secret yuz32314'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
login_manager = LoginManager(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#Initialize the db
db = SQLAlchemy(app)
db.create_all()

#Create a function to return string
class User (db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/login', methods=['GET','POST'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')

    if login and password:
        user = User.query.filter_by(login=login).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            next_page = request.args.get('next')

            return redirect(next_page)
        else:
            flash('Login or password is not correct')

    else:
        flash('Please fill login and password fields')

    return render_template('login.html')



@app.route('/register', methods=['GET','POST'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if request.method == 'POST':
        if not (login or password or password2):
            flash('Please fill all fields')
        elif password != password2:
            flash('Password are not equal!')
        else:
             hash_pwd = generate_password_hash(password)
             new_user = User(login=login, password=hash_pwd)
             db.session.add(new_user)
             db.session.commit()

             return redirect(url_for('login_page'))

    return render_template('register.html')


@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)

    return response



@app.route('/')
@login_required
def index():
    title = "WebServ"
    return render_template("server.html", title=title)



@app.route('/mqtt')
@login_required
def mqtt():
    title = "Client"
    os.system('python mqtt.py')
    print("python -u mqtt.py > output.txt")

    return render_template("Mqtt.html", title=title)


if __name__ == "__main__":
    app.run(debug=True)





