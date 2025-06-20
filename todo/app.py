from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
import urllib.parse
url = os.environ.get("DATABASE_URL", "sqlite:///todo.db")
if url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = url

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ----------------- MODELS -----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    priority = db.Column(db.Integer, nullable=True)
    assigned_to = db.Column(db.String(80))
    created_by = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    assign_date = db.Column(db.DateTime)
    deadline = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='Pending')

# ----------------- ROUTES -----------------
@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if user.role == 'admin':
        tasks = Task.query.filter_by(status='Pending').order_by(Task.assigned_to, Task.priority.asc().nulls_last()).all()
        users = User.query.filter_by(role='user').all()
    else:
        tasks = Task.query.filter_by(assigned_to=user.username, status='Pending').order_by(Task.priority.asc().nulls_last()).all()
        users = []
    return render_template('dashboard.html', user=user, tasks=tasks, users=users)

@app.route('/update-profile', methods=['GET', 'POST'])
def update_profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()

    if request.method == 'POST':
        new_username = request.form['new_username']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password and new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('update_profile'))

        if new_username and new_username != user.username:
            if User.query.filter_by(username=new_username).first():
                flash('Username already taken.', 'danger')
                return redirect(url_for('update_profile'))
            user.username = new_username
            session['username'] = new_username  # Update session

        if new_password:
            user.password = generate_password_hash(new_password)

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('update_profile.html', user=user)


@app.route('/created-tasks')
def created_tasks():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = session['username']
    tasks = Task.query.filter_by(created_by=user).order_by(Task.created_at.desc()).all()
    return render_template('created_tasks.html', tasks=tasks)
@app.route('/completed-tasks', methods=['GET'])
def completed_tasks():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['username']).first()
    
    if current_user.role == 'admin':
        selected_user = request.args.get('user')
        if selected_user:
            tasks = Task.query.filter_by(assigned_to=selected_user, status='Completed').all()
        else:
            tasks = Task.query.filter_by(status='Completed').all()
        users = User.query.filter_by(role='user').all()
    else:
        tasks = Task.query.filter_by(assigned_to=current_user.username, status='Completed').all()
        users = []

    return render_template('completed_tasks.html', tasks=tasks, users=users, user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hashed_pw = generate_password_hash(password)
        user = User(username=username, password=hashed_pw, role=role)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/add-task', methods=['POST'])
def add_task():
    if 'username' not in session:
        return redirect(url_for('login'))
    content = request.form['content']
    created_by = session['username']
    new_task = Task(content=content, created_by=created_by)
    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/assign-task/<int:task_id>', methods=['POST'])
def assign_task(task_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if user.role != 'admin':
        flash('Unauthorized', 'danger')
        return redirect(url_for('home'))

    task = Task.query.get(task_id)
    new_priority = int(request.form['priority'])
    assigned_to = request.form['assigned_to']
    deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')

    user_tasks = Task.query.filter(Task.id != task_id, Task.assigned_to == assigned_to).order_by(Task.priority).all()

    updated_tasks = []
    inserted = False
    current_priority = 1

    for t in user_tasks:
        if current_priority == new_priority:
            updated_tasks.append((task, new_priority))
            inserted = True
            current_priority += 1
        updated_tasks.append((t, current_priority))
        current_priority += 1

    if not inserted:
        updated_tasks.append((task, current_priority))

    for idx, (t, p) in enumerate(updated_tasks, 1):
        t.priority = idx

    task.assigned_to = assigned_to
    task.assign_date = datetime.utcnow()
    task.deadline = deadline
    task.status = 'Pending'
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/complete-task/<int:task_id>', methods=['POST'])
def complete_task(task_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    task = Task.query.get_or_404(task_id)
    if task.assigned_to != session['username']:
        flash('Unauthorized', 'danger')
        return redirect(url_for('home'))
    task.status = 'Completed'
    db.session.commit()
    return redirect(url_for('completed_tasks'))

@app.route('/edit-description/<int:task_id>', methods=['POST'])
def edit_description(task_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    task = Task.query.get_or_404(task_id)
    if session['username'] != task.created_by and User.query.filter_by(username=session['username']).first().role != 'admin':
        flash('Unauthorized to edit this task', 'danger')
        return redirect(url_for('home'))
    task.content = request.form['new_content']
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/delete-task/<int:task_id>')
def delete_task(task_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    task_to_delete = Task.query.get(task_id)
    if task_to_delete:
        db.session.delete(task_to_delete)
        db.session.commit()
        user_tasks = Task.query.filter_by(assigned_to=task_to_delete.assigned_to).order_by(Task.priority.asc().nulls_last()).all()
        for index, task in enumerate(user_tasks, start=1):
            task.priority = index
        db.session.commit()
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

