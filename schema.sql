CREATE TABLE IF NOT EXISTS users(
	u_id VARCHAR(36) PRIMARY KEY UNIQUE NOT NULL,
	username TEXT UNIQUE NOT NULL,
    email VARCHAR(100),
	password VARCHAR(100) NOT NULL,
	p_id VARCHAR(36) NOT NULL,
	overwatcher BOOLEAN DEFAULT 0 NOT NULL
);
CREATE INDEX user_search ON users (username, email);

CREATE TABLE IF NOT EXISTS messages(
	id VARCHAR(36) PRIMARY KEY NOT NULL,
	sender VARCHAR(36) NOT NULL,
	reciever VARCHAR(36) NOT NULL,
	message VARCHAR(10000) NOT NULL,
	FOREIGN KEY (sender) REFERENCES users(id),
	FOREIGN KEY (reciever) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS namespaces(
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    users VARCHAR(73) NOT NULL /* Store both users as space-seperated UUIDs */
);
CREATE INDEX namespace_users ON namespaces (users);