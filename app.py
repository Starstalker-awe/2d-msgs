from flask import Flask, render_template as render, request, session, redirect, url_for as url
from datetime import timedelta, datetime
import flask_socketio as socketio
from passlib.hash import argon2
from dotmap import DotMap
import flask_session
import functools
import threading
import tempfile
import requests
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
EXPLOITS = cs50.SQL("sqlite:///data.db")
PASSWORDS = CONNECTED = {u_id: None for u_id in map(lambda u:u['u_id'], DB.execute("SELECT * FROM users WHERE 1 = 1"))} # Connected to 
HASH_SETTINGS = {'rounds': 128, 'digest_size': 41, 'salt_size': 8}
EMAIL_REGEX = re.compile(r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+")


def login_required(f): # Wrapper for Flask routes
	@functools.wraps(f)
	def deced(*args, **kwargs):
		if (u := session.get("u_id")) == None or session.get('p_id') != next(iter(DB.execute("SELECT p_id FROM users WHERE u_id = ?", u)), {}).get("p_id"):
			return redirect(url("login"))
		return f(*args, **kwargs)

	@functools.wraps(f)
	def deced2(*args, **kwargs):
		print("Session id:", session.get("u_id"))
		if session.get("u_id") and next(iter(DB.execute("SELECT p_id FROM users WHERE u_id = ?")), {}).get("p_id") == session.get("p_id"):
			return f(*args, **kwargs)
		return redirect(url("login"))
	return deced2

def log_exploit(exp: str, ip: str):
	EXPLOITS.execute("INSERT INTO exploits (id, ip, descrip) VALUES (:id, :ip, :desc)", id=(expl := uuid.uuid4().hex), ip=ip, desc=exp)
	threading.Thread(target=EXPLOITS.execute("UPDATE exploits SET chance = :chance WHERE id = :id", id=expl, chance=c if (c := DotMap(requests.get(url="https://check.getipintel.net/check.php", params={'ip': ip, 'contact': 'travelingtrevor123@gmail.com', 'flags': 'f', 'format': 'json'}).json()).result) > -0.01 else None)).start()


# ==== User Handling Routes ====
@app.route("/login", methods = ['GET', 'POST']) # Handle both methods
def login():
	if request.method == 'POST':
		username = form.username.lower() if re.fullmatch(EMAIL_REGEX, (form := DotMap(json.loads(request.data))).username) else form.username
		if user := DotMap(next(iter(DB.execute("SELECT * FROM users WHERE username = :un OR lower(email) = :un", un=username)), {})).get("u_id"): # Verify that user exists
			if PASSWORDS[user.u_id] and PASSWORDS[user.u_id] == form.password or argon2.verify(form.password, user.password):
				session.update({"u_id": user.u_id, "p_id": user.p_id, "loggedin": datetime.now().timestamp(), "username": form.username}) # Update user session
				PASSWORDS[user.u_id] = form.password
				return {"data": {"error": None, "u_id": user.u_id}}
		return {"data": {"error": True}}
	return render("users/login.html") # Render page

@app.route("/register", methods = ['GET', 'POST']) # Handle get and post
def register():
	if request.method == 'POST':
		if all(k in (form := DotMap(json.loads(request.data))).keys() for k in ['username', 'password', 'confirm']):
			if form.password != form.confirm: return {"data": {"error": 1}}
			username = form.username.lower() if re.fullmatch(EMAIL_REGEX, (form := DotMap(json.loads(request.data))).username) else form.username
			if len(DB.execute("SELECT * FROM users WHERE username = :un OR lower(email) = :un", un=username)) == 0: # Make sure username isn't taken
				udata = {
					"u_id": uuid.uuid4().hex, 	# Unique user id
					"username": form.username, 	# Username which is required
					"email": form.email, 		# Email which may equal None
					"p_id": uuid.uuid4().hex 	# Change on password modification to allow "logout everywhere"
				} # Create dict of user's data
				DB.execute("INSERT INTO users (u_id, username, email, p_id) VALUES (:u_id, :username, :email, :p_id)", **udata)
				user = DotMap(next(iter(DB.execute("SELECT * FROM users WHERE u_id = ?", udata['u_id']))))
				threading.Thread(target=lambda:DB.execute("UPDATE users SET password = :pw WHERE u_id = :id", pw=argon2.using(**HASH_SETTINGS).hash(form.password), id=user.u_id)).start()
				session.update({"u_id": user.u_id, "p_id": user.p_id, "loggedin": datetime.now().timestamp(), "username": form.username})
				return {"data": {"error": None, "u_id": user.u_id}} # Return "completed"
			return {"data": {"error": 2}} 							# Username/email used
		log_exploit("Altered required for registration", request.remote_addr)
		return {"data": {"error": 3}} 								# Not all fields supplied
	return render("users/register.html") 							# Render registration page

@app.route("/logout")
def logout():
	session.clear(); return redirect(url("index"))


# ==== Messaging Routes ====
@login_required
@app.route("/messages", methods=["GET"])
def messages():
	@socket_.on("connect", namespace=request.path) # Active connected
	def conn(): CONNECTED[(uid := session['u_id'])] = request.sid; socket_.emit("status", {uid: True}, broadcast=True, namespace=request.path)
	@socket_.on("disconnect", namespace=request.path) # Inactive disconnected
	def discon(): CONNECTED[(uid := request['u_id'])] = None; socket_.emit("status", {uid: False}, broadcast=True, namespace=request.path)

	if len(to := request.args.get("to")):
		@socket_.on("typing", naemspace=request.path)
		def typing(): socket_.send({"u_id": request["u_id"], "username": request["username"]}, to=CONNECTED[to], namespace=request.path)

		@socket_.on("message", namespace=request.path)
		def message(data): 
			if ['id', 'reciever', 'message', 'stamped'] not in data.keys(): # Don't allow breaking of SQL database
				log_exploit("Altered socket fields", request.remote_addr)
				socket_.send({"data": "Altered socket fields!"}, to=request.sid)
				socketio.disconnect(sid=request.sid, namespace=request.path)

			if to != (data := DotMap(data)).reciever: # Don't allow sending to blocked user through modification of socket data
				log_exploit("Altered socket id", request.remote_addr)
				socket_.send({"data": "Altered socket id"})
				socketio.disconnect(sid=request.sid, namespace=request.path)

			DB.execute("INSERT INTO messages (id, sender, reciever, message, stamped, reply) VALUES (:id, :sender, :reciever, :message, :stamped, :reply)", **data, sender=session['u_id'])
			if (tos := CONNECTED[to]): 
				socket_.send({**data, 'sender': request['u_id']}, namespace=request.path, to=tos)
			socket_.send(True, to=request.sid, namespace=request.path)
		
		return render("conversation.html")
	return render("conversations.html")

@login_required
@app.route("/api/load_msgs", methods=["GET", "POST"])
def load_messages(): return DB.execute("SELECT * FROM messages WHERE (sender = :tu AND reciever = :ou) OR (sender = :ou AND reciever = :tu) ORDER BY stamped DESC LIMIT 50, :off", tu=session['u_id'], ou=(data := request.get_json(force=True))['to'] or request.args.get("to"), off=(data.get("offset") or 0)*50)

@login_required
@app.route("/api/load_convos", methods=["GET", "POST"])
def load_convos(): return DB.execute("SELECT u_id, username, pfp, SUBSTR(messages.message, 0, 200), messages.stamped FROM users WHERE u_id IN (SELECT DISTINCT sender, reciever FROM messages WHERE ((sender = :r AND reciever = :s) OR (sender = :s AND reciever = :r))) INNER JOIN messages ON messages.id = (SELECT id FROM messages WHERE ((sender = :r AND reciever = :s) OR (sender = :s AND reciever = :r)) ORDER BY stamped DESC LIMIT 1)", s=session['u_id'], r=(data := request.get_json(force=True))['to'] or request.args.get('to'), off=(data['offset'] or 0)*20)
		

# ==== Run Server ====
if __name__ == "__main__":
	socket_.run(app, debug=DEBUG, **({"keyfile": "key.pem", "certfile": "cert.pem"} if SECURE else {}))