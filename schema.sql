CREATE TABLE IF NOT EXISTS users(
	u_id VARCHAR(36) PRIMARY KEY UNIQUE NOT NULL,
	username TEXT UNIQUE NOT NULL,
    email VARCHAR(100),
	password VARCHAR(100) NOT NULL,
	p_id VARCHAR(36) NOT NULL,
	overwatcher BOOLEAN DEFAULT 0 NOT NULL
);
CREATE INDEX IF NOT EXISTS user_search ON users (username, email);

CREATE TABLE IF NOT EXISTS messages(
	id VARCHAR(36) PRIMARY KEY NOT NULL,
	sender VARCHAR(36) NOT NULL,
	namespace_id VARCHAR(36) NOT NULL,
	message VARCHAR(10000) NOT NULL,
	stamped TIMESTAMP NOT NULL,
	FOREIGN KEY (sender) REFERENCES users(id),
	FOREIGN KEY (namespace_id) REFERENCES namespaces(id)
);
CREATE INDEX IF NOT EXISTS message_content ON messages (message);

CREATE TABLE IF NOT EXISTS namespaces(
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    users VARCHAR(73) NOT NULL /* Store both users as space-seperated UUIDs */
);
CREATE INDEX IF NOT EXISTS namespace_users ON namespaces (users);