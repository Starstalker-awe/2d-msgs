from flask import Flask, render_template as render, request, session, redirect, url_for as url
from datetime import timedelta, datetime
import flask_socketio as socketio
from passlib.hash import argon2
from dotmap import DotMap
import flask_session
import functools
import threading
import tempfile
import json
import uuid
import cs50
import re

app = Flask(__name__)

ADMIN_SNOOPING = 	True
DEBUG = 			True
SECURE = 			False

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
socket_ = 			socketio.SocketIO(app, async_mode="eventlet", manage_session=False)
DB = 				cs50.SQL("sqlite:///data.db")
OVERWATCHERS = 		DB.execute("SELECT u_id FROM users WHERE overwatcher = 1") if ADMIN_SNOOPING else [] # Admins can see all messages...?
AUTHORIZED = 		{room: {id1: False, id2: False} for room, id1, id2 in [(a, *b.split(" ")) for a, b in DB.execute("SELECT * FROM namespaces")]}
HASH_SETTINGS = 	{'rounds': 128, 'digest_size': 41, 'salt_size': 8}
EMAIL_REGEX = 		re.compile(r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+")


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
	if request.method == 'POST':
		username = form.username.lower() if re.fullmatch(EMAIL_REGEX, (form := DotMap(json.loads(request.data))).username) else form.username
		if len(user := DB.execute("SELECT * FROM users WHERE username = :un OR lower(email) = :un", un = username)) == 1 and argon2.verify(form.password, user[0]['password']): # Verify credentials
			session.update({'u_id': user[0]['u_id'], 'p_id': user[0]['p_id'], "loggedin": datetime.now().timestamp()}) # Update user session
			return {"data": {"error": None, "u-id": user[0]['u_id']}}
		return {"data": {"error": True}}
	return render("login.html") # Render page

@app.route("/register", methods = ['GET', 'POST']) # Handle get and post
def register():
	if request.method == 'POST':
		if all(k in (form := DotMap(json.loads(request.data))).keys() for k in ['username', 'password', 'confirm']):
			if form.password != form.confirm: return {"data": {"error": 1}}
			username = form.username.lower() if re.fullmatch(EMAIL_REGEX, (form := DotMap(json.loads(request.data))).username) else form.username
			if len(DB.execute("SELECT * FROM users WHERE username = :un OR lower(email) = :un", un = username)) == 0: # Make sure username isn't taken
				udata = {
					"u_id": str(uuid.uuid4()), 	# Unique user id
					"username": form.username, 	# Username which is required
					"email": form.email, 		# Email which may equal None
					"p_id": str(uuid.uuid4()) 	# Change on password modification to allow "logout everywhere"
				} # Create dict of user's data
				DB.execute("INSERT INTO users (u_id, username, email, p_id) VALUES (:u_id, :username, :email, :p_id)", **udata)
				user = DotMap(DB.execute("SELECT * FROM users WHERE u_id = ?", udata['u_id'])[0])
				threading.Thread(target=lambda:DB.execute("UPDATE users SET password = :pw WHERE u_id = :id", pw = argon2.using(**HASH_SETTINGS).hash(form.password), id = user.u_id)).start()
				session.update({"u_id": user.u_id, "p_id": user.p_id, "loggedin": datetime.now().timestamp()})
				return {"data": {"error": None, "u_id": user.u_id}} # Return "completed"
			return {"data": {"error": 2}} 							# Username/email used
		return {"data": {"error": 3}} 								# Not all fields supplied
	return render("register.html") 									# Render registration page

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
			socket_.emit("verified", "true", namespace=NAMESPACE, to=request.sid) # Authorized to enter chat
			AUTHORIZED[space][uid] = True
		socket_.emit("verified", "false", namespace=NAMESPACE, to=request.sid) # Got room UUID, but unauthorized
		socketio.disconnect(namespace=NAMESPACE, sid=request.sid) # Terminate their connection

	@socket_.on("message", namespace=NAMESPACE)
	def message_sent(data): 
		data = DotMap(data)
		if AUTHORIZED[space][data.id]:
			socket_.emit("message", d := {"id": str(uuid.uuid4()), "msg": data.content, "sender": data.u_id, "time": data.timestamp})
			DB.execute("INSERT INTO MESSAGES (id, sender, namespace_id, message, stamped) VALUES (:id, :sender, :space, :msg, :time)", **{"space": space, **d})
	return render("index.html")
		

# ==== Run Server ====
if __name__ == "__main__":
	socket_.run(app, debug=DEBUG, **({"keyfile": "key.pem", "certfile": "cert.pem"} if SECURE else {}))