from flask import Flask, render_template as render, request, session, redirect, url_for as url
import flask_socketio as socketio
from passlib.hash import argon2
import flask_session
import functools
import tempfile
import uuid
import cs50

app = Flask(__name__)

app.config.update({
    "TEMPLATES_AUTO_RELOAD": True,
	"SESSION_FILE_DIR": tempfile.mkdtemp(),
	"SESSION_TYPE": "filesystem",
	"SESSION_PERMAMENT": False,
	"JSONIFY_PRETTYPRINT_REGULAR": True,
	"SECRET_KEY": uuid.uuid4()
})

flask_session.Session(app)
socket_ = socketio.SocketIO(app)
DB = cs50.SQL("sqlite:///data.db")


def login_required(f):
	@functools.wraps(f)
	def deced(*args, **kwargs):
		if u := session.get("u_id") or session.get("p_id") != DB.execute("SELECT p_id FROM users WHERE id = ?", u):
			return redirect(url("login"))
		return f(*args, **kwargs)
	return deced



@app.route("/")
@login_required
def index():
	return render("index.html")

@app.route("/login", methods = ['GET', 'POST']) # Handle both methods
def login():
	if request.method == 'POST': # Submitting form
		form = request.form.to_dict() # Convert to dictionary instead of obscure object
		if len(user := DB.execute("SELECT * FROM users WHERE username = :un OR email = :un", un = form.username)) == 1 and argon2.verify(form.password, user.password): # Verify credentials
			session.update({'u_id': user.id, 'p_id': user.p_id}) # Update user session
			return redirect(url("index")) # Return to index
		return render("login.html", error = True) # Invalid login credentials
	return render("login.html") # Render page

@app.route("/register", methods = ['GET', 'POST']) # Handle get and post
def register():
	if request.method == 'POST': # Submitting form
		form = request.form.to_dict() # Convert to dictionary for easier access
		if form.password != form.confirm: return render("register.html", error = 1) # Check if passwords match
		if len(DB.execute("SELECT * FROM users WHERE username = :un OR email = :un", un = form.username)) == 0: # Make sure username isn't taken
			data = {
				"u_id": uuid.uuid4(), # Unique user id
				"username": form.username, # Username which is required
				"email": form.email, # Email which may equal None
				"password": argon2.using(rounds=128,digest_size=41,salt_size=8).hash(form.password), # Hash to 100 characters
				"p_id": uuid.uuid4() # Change on password modification to allow "logout everywhere"
			} # Create dict of user's data
			user = DB.execute("INSERT INTO users (u_id, username, email, password, p_id) VALUES (:u_id, :username, :email, :password, :p_id)", **data) # Create DB entry
			session.update({"id": user.id, "p_id": user.p_id}) # Update session with necessary values, bypassing login
			return redirect(url("index")) # Send to index
		return render("register.html", error = 2) # Username is taken
	return render("register.html") # Render registration page


@login_required
@socketio.on('verify connection')
@app.route("/thread/<uuid:thread>")
def thread(room: uuid.UUID):
	if DB.execute("SELECT id FROM rooms WHERE users LIKE '%:u_id%' AND id = :r_id", u_id = session.get("u_id"), r_id = str(room)) is not None:
		socketio.join_room(room, room, f"/thread/{room}")
		socketio.send(f"{DB.execute('SELECT username FROM users WHERE id = ?', session.get('u_id'))} has logged on!", to=room)

if __name__ == "__main__":
	socket_.run(app)