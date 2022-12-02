CREATE TABLE IF NOT EXISTS users(
	u_id VARCHAR(32) PRIMARY KEY UNIQUE NOT NULL,
	username TEXT NOT NULL,
	bio TEXT,
    email TEXT,
	public TINYINT DEFAULT 1 NOT NULL,
	password VARCHAR(150),
	pfp TEXT, # Base64 encoded pfp
	p_id VARCHAR(32) NOT NULL,
	admin BOOLEAN DEFAULT 0 NOT NULL,
	active BOOLEAN DEFAULT 1 NOT NULL,
	created DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
	last_login DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS user_search ON users (username, email);

CREATE TABLE IF NOT EXISTS blocked(
	id VARCHAR(32) PRIMARY KEY NOT NULL,
	blocker VARCHAR(32) NOT NULL,
	blockee VARCHAR(32) NOT NULL,
	FOREIGN KEY (blocker) REFERENCES users(id),
	FOREIGN KEY (blockee) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS blocked_users ON blocked (blocker, blockee);

CREATE TABLE IF NOT EXISTS messages(
	id VARCHAR(32) PRIMARY KEY NOT NULL,
	sender VARCHAR(32) NOT NULL,
	reciever VARCHAR(32) NOT NULL,
	reply VARCHAR(32),
	message VARCHAR(10000) NOT NULL,
	stamped DATETIME NOT NULL,
	FOREIGN KEY (sender) REFERENCES users(id),
	FOREIGN KEY (reciever) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS message_id ON messages (id);
CREATE INDEX IF NOT EXISTS message_content ON messages (message);
CREATE INDEX IF NOT EXISTS message_conversation ON messages (sender, reciever);