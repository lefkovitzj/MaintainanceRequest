# Python Standard Library Module Imports.
import csv
import datetime
import hashlib
import os

# Third-party Module Imports.
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, flash, send_file
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy

def send_mail(to, subject, template):
    """ Wrapper function for email sending within Flask routes. """
    msg = Message(subject, recipients=[to], html=template, sender=app.config["MAIL_DEFAULT_SENDER"])
    mail.send(msg)
def sha_hash(string_to_hash):
    """ Wrapper function for hashlib's SHA-512 hash. """
    m = hashlib.sha3_512()
    m.update(bytes(string_to_hash, "utf-8"))
    return m.hexdigest()

""" Create a flask app. """
app = Flask(__name__)
load_dotenv() # Load the .env file's contents as environment variables.

# Configure the Owner Account.
app.config["OWNER_NAME"] = os.getenv("OWNER_NAME")
app.config["OWNER_EMAIL"] = os.getenv("OWNER_EMAIL")
app.config["OWNER_PASS_HASH"] = os.getenv("OWNER_PASS_HASH")

# Configure flask-sqlalchemy.
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SECURITY_PASSWORD_SALT"] = os.getenv("SECURITY_PASSWORD_SALT")
db = SQLAlchemy()
db.init_app(app)

# Configure flask-login.
login_manager = LoginManager()
login_manager.init_app(app)

# Configure flask-mail.
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER")
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
app.config["MAIL_PORT"] = os.getenv("MAIL_PORT")
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_USE_SSL"] = os.getenv("MAIL_USE_SSL")
mail = Mail(app)

# Configure manual database settings.
app.config["MAX_RECENT_ACTIONS"] = os.getenv("MAX_RECENT_ACTIONS")
app.config["MAX_RECENT_TASKS"] = os.getenv("MAX_RECENT_TASKS")


# Define database management wrapper functions.
def update_recent_tasks(recent_task): # Add a new action to the RecentTasks database table.
    """ Remove the oldest entry (if needed) and add the new one. """
    if recent_task.id not in [task.id for task in RecentTasks.query.all()]: # Skip if the task is already considered "Recent"
        if len(RecentTasks.query.all()) > (int(app.config["MAX_RECENT_TASKS"]) - 1): # Trim RecentTasks to max entries.
            for i in range(len(RecentTasks.query.all()) - (int(app.config["MAX_RECENT_TASKS"]) - 1)):
                earliest_entry = RecentTasks.query.order_by(RecentTasks.created_at).first()
                if earliest_entry:
                    db.session.delete(earliest_entry)
                    db.session.commit()
        db.session.add(recent_task) # Add and commit the new RecentTasks entry.
        db.session.commit()

def update_recent_actions(recent_action): # Add a new action to the RecentActions database table.
    """ Remove the oldest entry (if needed) and add the new one. """
    if len(RecentActions.query.all()) > (int(app.config["MAX_RECENT_ACTIONS"]) - 1): # Trim RecentActions to max entries.
        for i in range(len(RecentActions.query.all()) - (int(app.config["MAX_RECENT_ACTIONS"]) - 1)):
            earliest_entry = RecentActions.query.order_by(RecentActions.created_at).first()
            if earliest_entry:
                db.session.delete(earliest_entry)
                db.session.commit()
    db.session.add(recent_action) # Add and commit the new RecentActions entry.
    db.session.commit()

# Define database tables.
class Users(UserMixin, db.Model):
    """ Store all Users in the database. """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique = True, nullable = False)
    password = db.Column(db.String(64), nullable = False)
    email = db.Column(db.String(250), nullable = False)
    priviledge_level = db.Column(db.String(64), nullable = False)

class Tasks(db.Model):
    """ Store all Tasks in the database. """
    id = db.Column(db.Integer, primary_key=True)
    urgency = db.Column(db.Integer, nullable=False)
    for_user = db.Column(db.String(250), nullable=False)
    status = db.Column(db.String(250), nullable = False)
    description = db.Column(db.String(500), nullable = False)
    location = db.Column(db.String(250), nullable=True)
    delegated_to = db.Column(db.String(250), nullable=True)

class RecentActions(db.Model):
    """ Store a list of (max MAX_RECENT_ACTIONS entries) recent actions. """
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    fa_icon = db.Column(db.String(250), nullable=False)
    description = db.Column(db.String(250), nullable=False)
    link_url = db.Column(db.String(250), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class RecentTasks(db.Model):
    """ Store a list of (max MAX_RECENT_TASKS entries) recently-modified Tasks. """
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    task_id = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(250), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

with app.app_context():
    db.create_all()


# User management routes.
@login_manager.user_loader
def loader_user(user_id):
    """ Flask-Login login manager in combination with Flask-SQL-Alchemy """
    return Users.query.get(user_id)

@app.route("/login", methods = ["GET","POST"])
def login(): # None
    """ Authenticate. """
    if request.method == "POST":
        user = Users.query.filter_by(username=request.form.get("username")).first()
        if user != None:
            if user.password == sha_hash(request.form.get("password")):
                login_user(user)
                return redirect(url_for("dashboard"))
        elif request.form.get("username") == app.config["OWNER_NAME"] and sha_hash(request.form.get("password")) == app.config["OWNER_PASS_HASH"]:
            user = Users(username=app.config["OWNER_NAME"], password = app.config["OWNER_PASS_HASH"], email = app.config["OWNER_EMAIL"], priviledge_level = "owner")
            db.session.add(user)
            db.session.commit()
            return redirect(url_for("dashboard"))
        else:
            return "Unauthorized access denied.", 401
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout(): # Owner, Admin, Helper, User
    """ De-authenticate. """
    logout_user()
    return redirect(url_for("home"))

# Database-related dashboard routes.
@app.route("/export-tasks")
@login_required
def export_tasks():
    if current_user.priviledge_level == "owner" or current_user.priviledge_level == "admin": # The user has "owner" or "admin" priviledges.
        task_data = Tasks.query.all()
        with open("task-export.csv", "w", newline="") as csv_export:
            csv_writer = csv.writer(csv_export, delimiter=",")
            csv_writer.writerow(["Description","User for","Delegated to", "Location", "Urgency","Status"])
            for task_r in task_data:
                csv_writer.writerow([task_r.description, task_r.for_user, task_r.delegated_to, task_r.location, task_r.urgency, task_r.status])
        return send_file("task-export.csv", mimetype="text/csv", download_name="Task Data Export.csv", as_attachment=True)
    else: # Unauthorized access.
        return "Unauthorized access denied.", 401

@app.route("/remove-completed")
@login_required
def remove_completed():
    if current_user.priviledge_level == "owner" or current_user.priviledge_level == "admin": # The user has "owner" or "admin" priviledges.
        task_data = Tasks.query.filter_by(status = "Completed").all()
        removed_task_ids = []
        for task in task_data:
            removed_task_ids.append(task.id)
            db.session.delete(task)
        for recent_task in RecentTasks.query.all(): # Remove any "completed" tasks from the RecentTasks table.
            if recent_task.task_id in removed_task_ids:
                db.session.delete(recent_task)
        db.session.commit()
        return redirect(url_for("dashboard"))
    else: # Unauthorized access.
        return "Unauthorized access denied.", 401

@app.route("/remove-cancelled")
@login_required
def remove_cancelled():
    if current_user.priviledge_level == "owner" or current_user.priviledge_level == "admin": # The user has "owner" or "admin" priviledges.
        task_data = Tasks.query.filter_by(status = "Cancelled").all()
        removed_task_ids = []
        for task in task_data:
            removed_task_ids.append(task.id)
            db.session.delete(task)
        for recent_task in RecentTasks.query.all(): # Remove any "cancelled" tasks from the RecentTasks table.
            if recent_task.task_id in removed_task_ids:
                db.session.delete(recent_task)
        db.session.commit()
        return redirect(url_for("dashboard"))
    else: # Unauthorized access.
        return "Unauthorized access denied.", 401

""" Pages that require a logged-in user. """
@app.route("/dashboard")
@login_required
def dashboard(): # Owner, Admin, Helper, User
    """ User dashboard. """
    if current_user.priviledge_level == "owner" or current_user.priviledge_level == "admin": # The user has "owner" or "admin" priviledges.
        owner_actions = ["add user", "edit user", "remove user", "delegate task", "complete task", "cancel task", "edit task", "create task", "view tasks"]
        admin_actions = ["add user", "edit user", "remove user", "delegate task", "complete task", "cancel task", "edit task", "create task", "view tasks"]
        helper_actions = ["complete task", "cancel task", "edit task", "create task", "view tasks"]
        user_actions = ["cancel task", "edit task", "create task", "view tasks"]

        available_actions = ["edit task", "create task", "view task"]
        available_tasks = []
        recent_tasks = []
        recent_activity = []

        recent_activity = RecentActions.query.all()
        recent_tasks_data = RecentTasks.query.all()
        num_tasks = len(Tasks.query.all())
        num_users = len(Users.query.all())

        for recent_task_value in recent_tasks_data:
            recent_task_obj = Tasks.query.filter_by(id = recent_task_value.task_id).first()
            if recent_task_obj != None:
                recent_tasks.append((recent_task_obj, recent_task_value.description))
        recent_activity.reverse()
        recent_tasks.reverse()
        return render_template("admin_dash.html", recent_tasks = recent_tasks, recent_activity = recent_activity, num_tasks = num_tasks, num_users = num_users)
    else:
        return view_tasks()


@app.route("/statistics")
@login_required
def view_statsistics():  # Owner, Admin
    """ View all tasks available to the user. """
    if current_user.priviledge_level == "owner" or current_user.priviledge_level == "admin": # The user has "owner" or "admin" priviledges.
        all_tasks = Tasks.query.all()
        active_tasks = Tasks.query.filter_by(status = "Active").all()
        completed_tasks = Tasks.query.filter_by(status = "Completed").all()
        cancelled_tasks = Tasks.query.filter_by(status = "Cancelled").all()
        num_users = len(Users.query.filter_by(priviledge_level = "user").all())
        num_admins = len(Users.query.filter_by(priviledge_level = "admin").all())
        num_helpers = len(Users.query.filter_by(priviledge_level = "helper").all())
        print(num_users, num_helpers, num_admins)
        return render_template("statistics.html", active_tasks = len(active_tasks), completed_tasks = len(completed_tasks), cancelled_tasks = len(cancelled_tasks), num_users = num_users, num_helpers = num_helpers, num_admins = num_admins)

    else: # Unauthorized access.
        return "Unauthorized access denied.", 401

@app.route("/view-users")
@login_required
def view_users():  # Owner, Admin
    """ View all users registered to the database. """
    if current_user.priviledge_level == "owner" or current_user.priviledge_level == "admin": # The user has "owner" or "admin" priviledges.
        helpers = Users.query.filter_by(priviledge_level="helper").all()
        users = Users.query.filter_by(priviledge_level="user").all()
        usernames = {"Helper": [helper.username for helper in helpers], "Users": [user.username for user in users]}
        numbers = {"Helpers": len(helpers), "Users": len(users)}
        all_users = []
        for user_data in users:
            all_users.append(user_data)
        for user_data in helpers:
            all_users.append(user_data)
        if current_user.priviledge_level == "owner":
            admins = Users.query.filter_by(priviledge_level="admin").all()
            for user_data in admins:
                all_users.append(user_data)
            usernames["Admins"] = [admin.username for admin in admins]
            numbers["Admins"] = len(admins)

        return render_template("view_users.html", user_list = all_users)

    else: # Unauthorized access.
        return "Unauthorized access denied.", 401

@app.route("/view-tasks")
@login_required
def view_tasks():  # Owner, Admin, Helper, User
    """ View all tasks available to the user. """
    if current_user.priviledge_level == "owner" or current_user.priviledge_level == "admin": # The user has "owner" or "admin" priviledges.
        tasks = Tasks.query.all()
        return render_template("view_tasks.html", task_list=tasks)
    elif current_user.priviledge_level == "helper": # The current user has "helper" priviledges.
        tasks = Tasks.query.filter_by(for_user = current_user.username).all()
        my_delegated_tasks = Tasks.query.filter_by(delegated_to = current_user.username).all()
        undelegated_tasks = Tasks.query.filter_by(delegated_to = None).all()
        for task in my_delegated_tasks:
            tasks.append(task)
        for task in undelegated_tasks:
            tasks.append(task)
        return render_template("helper_dash.html", task_list=tasks)
    else: # The current user has "user" priviledges.
        tasks = Tasks.query.filter_by(for_user = current_user.username).all()
        return render_template("user_dash.html", task_list=tasks)

@app.route("/create-task", methods=["POST","GET"])
@login_required
def create_task():  # Owner, Admin, Helper, User
    """ Add a task via form submission. """
    if request.method == "POST":
        for_user = current_user.username
        status = "Active"
        urgency = request.form.get("urgency")
        location = request.form.get("location")
        description = request.form.get("description")
        if description.strip() !="" and location.strip() != "":
            task = Tasks(for_user = for_user, status = status, urgency = urgency, location = location, description = description)
            db.session.add(task)
            db.session.commit()
            recent_task = RecentTasks(task_id = task.id, description = "Task created!")
            update_recent_tasks(recent_task)
            return redirect(url_for("view_tasks"))
        else: # Retry.
            redirect(url_for("create_task"))
    return render_template("task_form.html")

@app.route("/cancel-task/<task_id>")
@login_required
def cancel_task(task_id):  # Owner, Admin, Helper, User
    """ Cancel the task with id "task_id" as long as the user is the Task's creator, the owner, or an admin. """
    select_task = Tasks.query.filter_by(id = task_id).first_or_404()
    if select_task.for_user == current_user.username or (current_user.priviledge_level == "owner" or current_user.priviledge_level == "admin" or select_task.delegated_to == current_user.username): # Check access permissions.
        select_task.status = "Cancelled" # Update and commit the data.
        db.session.commit()
        recent_task = RecentTasks(task_id = select_task.id, description = "Task cancelled!")
        update_recent_tasks(recent_task)
        for_user = Users.query.filter_by(username = select_task.for_user).first() # Get the task creator.
        if for_user != None and for_user.username != current_user.username: # There is a creator that isn't the current user.
            email_address = for_user.email
            html = f"""<h1>Task Notification</h1><br><br><h3>A Task you created was cancelled!<br><a href={request.url_root}view-tasks#task-{select_task.id}">View the Task</a>"""
            subject = "Task Cancelled"
            send_mail(email_address, subject, html) # Notify the task creator.
        return redirect(url_for("view_tasks"))
    else: # Unauthorized access.
        return "Unauthorized access denied.", 401

@app.route("/delegate-task/<task_id>", methods=["POST","GET"])
@login_required
def delegate_task(task_id):  # Owner, Admin
    """ Delegate the task with id "task_id" as long as the user is the owner or an admin. """
    select_task = Tasks.query.filter_by(id = task_id).first_or_404()
    if current_user.priviledge_level == "owner" or current_user.priviledge_level == "admin": # Check access permissions.
        helpers = Users.query.filter_by(priviledge_level = "helper").all()
        helper_names = [helper.username for helper in helpers]
        if current_user.priviledge_level == "owner":
            admins = Users.query.filter_by(priviledge_level = "admin").all()
            for admin in admins:
                helper_names.append(admin.username)
        if request.method == "POST": # POST Request (form submission).
            helpers = Users.query.filter_by(priviledge_level = "helper").all()
            delegate = request.form.get("delegate")
            if delegate.strip() != "" and delegate in helper_names:
                select_task.delegated_to = delegate # Update and commit the data.
                db.session.commit()
                recent_task = RecentTasks(task_id = select_task.id, description="Task delegated")
                update_recent_tasks(recent_task)
                for_user = Users.query.filter_by(username = delegate).first() # Get the delegated user.
                if for_user != None and for_user.username != current_user.username: # There is a delegate that isn't the current user.
                    email_address = for_user.email
                    html = f"""<h1>Task Notification</h1><br><br><h3>A Task was delegated to you!<br><a href="{request.url_root}view-tasks#task-{select_task.id}">View the Task</a>"""
                    subject = "Task Delegated"
                    send_mail(email_address, subject, html) # Notify the task creator.
                return redirect(url_for("view_tasks"))
        else: # GET Request.
            return render_template("delegate.html", usernames = helper_names, location_val = select_task.location, description_val = select_task.description)
    else: # Unauthorized access.
        return "Unauthorized access denied.", 401

@app.route("/edit-task/<task_id>", methods=["POST","GET"])
@login_required
def edit_task(task_id): # Owner, Admin, Helper, User
    """ Allow edits of the task with id "task_id" as long as the user is the Task's creator, the owner, or an admin. """
    select_task = Tasks.query.filter_by(id = task_id).first_or_404()
    if select_task.for_user == current_user.username or (current_user.priviledge_level == "owner" or current_user.priviledge_level == "admin" or select_task.delegated_to == current_user.username): # Check access permissions.
        if request.method == "POST": # POST Request (form submission).
            for_user = current_user.username
            status = "Active"
            urgency = request.form.get("urgency")
            location = request.form.get("location")
            description = request.form.get("description")
            if description.strip() !="" and location.strip() != "":
                select_task.urgency = urgency # Update and commit the data.
                select_task.location = location
                select_task.description = description
                db.session.commit()
                recent_task = RecentTasks(task_id = select_task.id, description = "Task edited!")
                update_recent_tasks(recent_task)
                for_user = Users.query.filter_by(username = select_task.for_user).first() # Get the task creator.
                if for_user != None and for_user.username != current_user.username: # There is a creator that isn't the current user.
                    email_address = for_user.email
                    html = f"""<h1>Task Notification</h1><br><br><h3>A Task you created was edited!<br><a href={request.url_root}view-tasks#task-{select_task.id}">View the Task</a>"""
                    subject = "Task Edited"
                    send_mail(email_address, subject, html) # Notify the task creator.
                return redirect(url_for("view_tasks"))
        else: # GET Request.
            return render_template("task_form.html", location_val=select_task.location, description_val=select_task.description, urgency=select_task.urgency)
    else: # Unauthorized access.
        return "Unauthorized access denied.", 401

@app.route("/complete-task/<task_id>")
@login_required
def complete_task(task_id): # Owner, Admin, Helper
    """ Complete the task with id "task_id" as long as the user is the Task's creator, the owner, or an admin. """
    select_task = Tasks.query.filter_by(id = task_id).first_or_404()
    if current_user.priviledge_level == "owner" or current_user.priviledge_level == "admin" or select_task.delegated_to == current_user.username or select_task.delegate_to == None: # Check access permissions.
        select_task.status = "Completed" # Update and commit the data.
        db.session.commit()
        recent_task = RecentTasks(task_id = select_task.id, description = "Taskk completed!")
        update_recent_tasks(recent_task)
        for_user = Users.query.filter_by(username = select_task.for_user).first() # Get the task creator.
        if for_user != None and for_user.username != current_user.username: # There is a creator that isn't the current user.
            email_address = for_user.email
            html = f"""<h1>Task Notification</h1><br><br><h3>A Task you created was completed!<br><a href={request.url_root}view-tasks#task-{select_task.id}">View the Task</a>"""
            subject = "Task Completed"
            send_mail(email_address, subject, html) # Notify the task creator.
        return redirect(url_for("view_tasks"))
    else: # Unauthorized access.
        return "Unauthorized access denied.", 401

@app.route("/add-user", methods = ['GET', 'POST'])
@login_required
def add_user(): # Owner, Admin
    """ Add a user via form submission as long as the user is the owner, or an admin. """
    allowed_priviledges = []
    if current_user.priviledge_level == "owner" or current_user.priviledge_level == "admin":
        allowed_priviledges = ["user","helper"]
        if current_user.priviledge_level == "owner":
            allowed_priviledges.append("admin")
    if request.method == 'POST':
        new_username = request.form.get("username").strip().replace(" ", "_")
        new_priviledge = request.form.get("priviledge")
        new_password = request.form.get("password")
        new_email = request.form.get("email").strip()
        if new_username.strip() !="" and new_password.strip() != "" and new_email.strip() != "" and new_priviledge.strip() != "":
            user = Users(username=new_username, password=sha_hash(new_password), email=new_email, priviledge_level=new_priviledge)
            db.session.add(user)
            db.session.commit()
            recent_action = RecentActions(fa_icon="fa-user-plus", description=f"New {new_priviledge} {new_username} added!", link_url=f"/view-users#user-{new_username}")
            update_recent_actions(recent_action)
            return redirect(url_for("dashboard"))
    else:
        if allowed_priviledges != []:
            return render_template("user_form.html", priviledges=allowed_priviledges)
        else:
            return "Unauthorized access denied.", 401

@app.route("/edit-user/<user_name>", methods = ['GET', 'POST'])
@login_required
def edit_user(user_name): # Owner, Admin
    """ Edit a user via form submission as long as the user is the owner, or an admin. """
    allowed_priviledges = []
    if current_user.priviledge_level == "owner" or current_user.priviledge_level == "admin":
        user = Users.query.filter_by(username = user_name).first_or_404()
        allowed_priviledges = ["user","helper"]
        if current_user.priviledge_level == "owner":
            allowed_priviledges.append("admin")

        if request.method == 'POST':
            new_priviledge = request.form.get("priviledge")
            new_password = request.form.get("password")
            new_email = request.form.get("email")
            if new_password.strip() != "" and new_email.strip() != "" and new_priviledge.strip() != "":
                user.priviledge_level = new_priviledge
                user.password = sha_hash(new_password)
                user.email = new_email
                db.session.commit()
                recent_action = RecentActions(fa_icon="fa-user", description=f"{new_priviledge.title()} {user_name} modified!", link_url=f"/view-users#user-{user_name}")
                update_recent_actions(recent_action)
                return redirect(url_for("dashboard"))
            else:
                return render_template("user_form.html", priviledges=allowed_priviledges, set_username = user_name)
        else:
            if allowed_priviledges != []:
                return render_template("user_form.html", priviledges=allowed_priviledges, set_username = user_name)
    else:
        return "Unauthorized access denied.", 401

@app.route("/remove-user/<user_name>")
@login_required
def remove_user(user_name): # Owner, Admin
    """ Remove a user as long as the user is the owner, or an admin. """
    if current_user.priviledge_level == "owner" or current_user.priviledge_level == "admin":
        user = Users.query.filter_by(username = user_name).first_or_404()
        if user.priviledge_level != "admin" or current_user.priviledge_level == "owner":
            db.session.delete(user)
            db.session.commit()
            recent_action = RecentActions(fa_icon="fa-user-times", description=f"{user.priviledge_level.title()} {user_name} removed!", link_url="/view-users")
            update_recent_actions(recent_action)
            return redirect("/")
        else:
            return "Unauthorized access denied.", 401
    else:
        return "Unauthorized access denied.", 401

@app.route("/")
def home(): # Owner, Admin, Helper, User, None.
    """ Return a login page or redirect to the user dashboard. """
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    else:
        return redirect(url_for("dashboard"))

@app.errorhandler(401)
def handle_401(e):
    """ Return a login page or error message. """
    if not current_user.is_authenticated:
        flash('Please log in to access this resource!')
        return redirect(url_for("login"))
    else:
        flash('You do not have permission to access to this page.')
        return redirect(url_for("dashboard"))
