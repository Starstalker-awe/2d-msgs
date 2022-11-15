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

DEBUG = True
SECURE = False

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
socket_ = socketio.SocketIO(app, async_mode="eventlet", manage_session=False)
DB = cs50.SQL("sqlite:///data.db")
CONNECTED, PASSWORDS = {u_id: None for u_id in map(lambda u:u['u_id'], DB.execute("SELECT * FROM users WHERE 1 = 1"))} # Connected to 
HASH_SETTINGS = {'rounds': 128, 'digest_size': 41, 'salt_size': 8}
EMAIL_REGEX = re.compile(r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+")


def login_required(f): # Wrapper for Flask routes
	@functools.wraps(f)
	def deced(*args, **kwargs):
		if (u := session.get("u_id")) == None or session.get('p_id') != next(iter(DB.execute("SELECT p_id FROM users WHERE u_id = ?", u)), {}).get("p_id"):
			return redirect(url("login"))
		return f(*args, **kwargs)
	return deced


# ==== User Handling Routes ====
@app.route("/login", methods = ['GET', 'POST']) # Handle both methods
def login():
	if request.method == 'POST':
		username = form.username.lower() if re.fullmatch(EMAIL_REGEX, (form := DotMap(json.loads(request.data))).username) else form.username
		if user := DotMap(next(iter(DB.execute("SELECT * FROM users WHERE username = :un OR lower(email) = :un", un = username)), {})).get("u_id"): # Verify that user exists
			if PASSWORDS[user.u_id] and PASSWORDS[user.u_id] == form.password or argon2.verify(form.password, user.password):
				session.update({'u_id': user[0]['u_id'], 'p_id': user[0]['p_id'], "loggedin": datetime.now().timestamp()}) # Update user session
				PASSWORDS[user[0]['u_id']] = form.password
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
					"u_id": uuid.uuid4().hex, 	# Unique user id
					"username": form.username, 	# Username which is required
					"email": form.email, 		# Email which may equal None
					"p_id": uuid.uuid4().hex 	# Change on password modification to allow "logout everywhere"
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
@app.route("/")
def messages():
	@socket_.on("connect", namespace="/messages")
	def conn(_): CONNECTED[session['u_id']] = request.sid; socket_.emit("verified", True, to=request.sid)
	return render("index.html")

@login_required
@app.route("/thread/<thread>")
def conversation(thread):
	@socket_.on("connect", namespace=request.path)
	def connection_handler(_):
		CONNECTED[session['u_id']] = request.sid
		socket_.emit("data", DB.execute("SELECT * FROM messages WHERE (sender = :tu AND reciever = :ou) OR (sender = :ou AND reciever = :tu) ORDER BY stamped DESC LIMIT 50", session.get("u_id"), thread))

	@socket_.on("message", namespace=request.path)
	def message(data):
		if ['id', 'reciever', 'message', 'stamped'] not in data.keys(): socket_.send({"data": "Altered socket send!"}, to=request.sid); socketio.disconnect(sid=request.sid, namespace=request.path)
		DB.execute("INSERT INTO messages (id, sender, reciever, message, stamped) VALUES (:id, :sender, :reciever, :message, :stamped)", **data, sender=session['u_id'])
		if CONNECTED[(data := DotMap(data)).reciever]:
			socket_.send({**data, 'sender': request['u_id']}, broadcast=True)
		else: socket_.send(True, to=request.sid)

	@socket_.on("disconnect", namespace=request.path)
	def discon_handler(_): CONNECTED[request.sid] = None
		

# ==== Run Server ====
if __name__ == "__main__":
	socket_.run(app, debug=DEBUG, **({"keyfile": "key.pem", "certfile": "cert.pem"} if SECURE else {}))