from flask import Flask, render_template as render, request, session, redirect, url_for as url
import flask_socketio as socketio
from passlib.hash import argon2
from datetime import timedelta, datetime
from dotmap import DotMap
import flask_session
import functools
import tempfile
import uuid
import cs50

app = Flask(__name__)

ADMIN_SNOOPING = True

app.config.update({
    "TEMPLATES_AUTO_RELOAD": True,
	"SESSION_FILE_DIR": tempfile.mkdtemp(),
	"SESSION_TYPE": "filesystem",
	"SESSION_PERMAMENT": True,
	"PERMANENT_SESSION_LIFETIME": timedelta(weeks=4), # Default one month session length
	"JSONIFY_PRETTYPRINT_REGULAR": True,
	"SECRET_KEY": uuid.uuid4().hex
})

flask_session.Session(app)
socket_ = socketio.SocketIO(app, async_mode="eventlet")
DB = cs50.SQL("sqlite:///data.db")
OVERWATCHERS = DB.execute("SELECT u_id FROM users WHERE overwatcher = 1") if ADMIN_SNOOPING else [] # Admins can see all messages...?
AUTHORIZED = {room: {id1: False, id2: False} for room, id1, id2 in [(a, *b.split(" ")) for a, b in DB.execute("SELECT * FROM namespaces")]}


def login_required(f): # Wrapper for Flask routes
	@functools.wraps(f)
	def deced(*args, **kwargs):
		if (u := session.get("u_id")) == None or session.get('p_id') != next(iter(DB.execute("SELECT p_id FROM users WHERE u_id = ?", u)), {}).get("p_id"):
			return redirect(url("login"))
		return f(*args, **kwargs)
	return deced



@app.route("/")
@login_required
def index():
	return render("index.html")

# ==== User Handling Routes ====
@app.route("/login", methods = ['GET', 'POST']) # Handle both methods
def login():
	if request.method == 'POST': # Submitting form
		form = DotMap(request.form.to_dict()) # Convert to dictionary instead of obscure object
		if len(user := DB.execute("SELECT * FROM users WHERE username = :un OR email = :un", un = form.username)) == 1 and argon2.verify(form.password, user[0]['password']): # Verify credentials
			session.update({'u_id': user[0]['u_id'], 'p_id': user[0]['p_id'], "loggedin": datetime.now().timestamp()}) # Update user session
			return redirect(url("index")) # Return to index
		return render("login.html", error = True) # Invalid login credentials
	return render("login.html") # Render page

@app.route("/register", methods = ['GET', 'POST']) # Handle get and post
def register():
	if request.method == 'POST': # Submitting form
		form = DotMap(request.form.to_dict()) # Convert to dictionary for easier access
		if form.password != form.confirm: return render("register.html", error = 1) # Check if passwords match
		if len(DB.execute("SELECT * FROM users WHERE username = :un OR email = :un", un = form.username)) == 0: # Make sure username isn't taken
			data = {
				"u_id": str(uuid.uuid4()), # Unique user id
				"username": form.username, # Username which is required
				"email": form.email, # Email which may equal None
				"password": argon2.using(rounds=128,digest_size=41,salt_size=8).hash(form.password), # Hash to 100 characters
				"p_id": str(uuid.uuid4()) # Change on password modification to allow "logout everywhere"
			} # Create dict of user's data
			user = DB.execute("INSERT INTO users (u_id, username, email, password, p_id) VALUES (:u_id, :username, :email, :password, :p_id)", **data) # Create DB entry
			print(user)
			session.update({"id": user.id, "p_id": user.p_id, "loggedin": datetime.now().timestamp()}) # Update session with necessary values, bypassing login
			return redirect(url("index")) # Send to index
		return render("register.html", error = 2) # Username is taken
	return render("register.html") # Render registration page

@app.route("/logout")
def logout():
	session.clear(); return redirect(url("index"))


# ==== Socket Routes ====
@login_required
@app.route("/thread/<uuid:space>")
def conversation(space):
	NAMESPACE = f"/thread/{space}"
	@socket_.on("verify", namespace=NAMESPACE)
	def verify_connection(_):
		if DB.execute("SELECT id FROM namespaces WHERE users LIKE ?", f"%{session.get('u_id')}%") == space or (uid := session.get("u_id") in OVERWATCHERS):
			socket_.emit("verified", "true", namespace=NAMESPACE) # Authorized to enter chat
			AUTHORIZED[space][uid] = True
		socket_.emit("verified", "false", namespace=NAMESPACE) # Got room UUID, but unauthorized

	@socket_.on("message", namespace=NAMESPACE)
	def message_sent(data): 
		data = DotMap(data)
		if AUTHORIZED[space][data.id]:
			socket_.emit("message", d := {"id": str(uuid.uuid4()), "msg": data.content, "sender": data.u_id, "time": data.timestamp})
			DB.execute("INSERT INTO MESSAGES (id, sender, namespace_id, message, stamped) VALUES (:id, :sender, :space, :msg, :time)", **{"space": space, **d})
	return render("index.html")
		

# ==== Run Server ====
if __name__ == "__main__":
	socket_.run(app, debug=True)