from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from database import db, User, Complaint

app = Flask(__name__)
app.config['SECRET_KEY'] = 'resolve_secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- ROUTES ----------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        user = User(
            name=request.form['name'],
            email=request.form['email'],
            password=generate_password_hash(request.form['password']),
            role="user"
        )
        db.session.add(user)
        db.session.commit()
        flash("Registration successful")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash("Invalid login")
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/submit', methods=['GET','POST'])
@login_required
def submit():
    if request.method == 'POST':
        complaint = Complaint(
            user_id=current_user.id,
            title=request.form['title'],
            description=request.form['description']
        )
        db.session.add(complaint)
        db.session.commit()
        flash("Complaint submitted")
        return redirect(url_for('my_complaints'))
    return render_template('submit_complaint.html')

@app.route('/my_complaints')
@login_required
def my_complaints():
    complaints = Complaint.query.filter_by(user_id=current_user.id).all()
    return render_template('my_complaints.html', complaints=complaints)

@app.route('/admin')
@login_required
def admin():
    if current_user.role != "admin":
        return redirect(url_for('dashboard'))
    complaints = Complaint.query.all()
    return render_template('admin_dashboard.html', complaints=complaints)

@app.route('/assign/<int:id>', methods=['POST'])
@login_required
def assign(id):
    complaint = Complaint.query.get(id)
    complaint.assigned_agent = request.form['agent']
    complaint.status = "In Progress"
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
