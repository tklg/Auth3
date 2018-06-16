CREATE TABLE auth3_users (
	id INT NOT NULL AUTO_INCREMENT,
	uuid CHAR(36),
	email VARCHAR(128),
	password VARCHAR(255),
	first_name VARCHAR(128),
	family_name VARCHAR(128),
	twofactor VARCHAR(16) DEFAULT NULL,
	using_twofactor TINYINT DEFAULT '0',
	verification_status VARCHAR(40) DEFAULT 'false',
	join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
	UNIQUE (uuid)
) charset=utf8 ENGINE=INNODB;

CREATE TABLE auth3_clients (
	id INT NOT NULL AUTO_INCREMENT,
	client_name VARCHAR(80),
	client_display VARCHAR(80),
	client_secret VARCHAR(80),
	redirect_uri VARCHAR(2048),
	grant_types VARCHAR(80),
	user_id INT,
	FOREIGN KEY (user_id)
		REFERENCES auth3_users(id)
		ON DELETE CASCADE,
	PRIMARY KEY (id)
) charset=utf8 ENGINE=INNODB;

CREATE TABLE auth3_access_tokens (
	id INT NOT NULL AUTO_INCREMENT,
	user_id INT,
	FOREIGN KEY (user_id)
		REFERENCES auth3_users(id)
		ON DELETE CASCADE,
	client_id INT,
	FOREIGN KEY (client_id)
		REFERENCES auth3_clients(id)
		ON DELETE CASCADE,
	access_token VARCHAR(128),
	access_token_raw VARCHAR(512),
	scopes VARCHAR(2048),
	is_revoked TINYINT(1) DEFAULT '0',
	ip_address CHAR(16),
	browser VARCHAR(64),
	operating_system VARCHAR(64),
	country VARCHAR(128),
	device VARCHAR(64),
	created TIMESTAMP
		DEFAULT CURRENT_TIMESTAMP,
	expires TIMESTAMP 
		DEFAULT CURRENT_TIMESTAMP
		ON UPDATE CURRENT_TIMESTAMP,
	UNIQUE (access_token),
	PRIMARY KEY (id)
) charset=utf8 ENGINE=INNODB;

CREATE TABLE auth3_refresh_tokens (
	id INT NOT NULL AUTO_INCREMENT,
	refresh_token VARCHAR(128),
	access_token VARCHAR(128),
	refresh_token_raw VARCHAR(512),
	is_revoked TINYINT(1) DEFAULT '0',
	expires TIMESTAMP 
		DEFAULT CURRENT_TIMESTAMP
		ON UPDATE CURRENT_TIMESTAMP,
	UNIQUE (refresh_token),
	CHECK (access_token IN (SELECT access_token FROM auth3_access_tokens)),
	PRIMARY KEY (id)
) charset=utf8 ENGINE=INNODB;

CREATE TABLE auth3_authorization_codes (
	id INT NOT NULL AUTO_INCREMENT,
	user_id INT,
	FOREIGN KEY (user_id)
		REFERENCES auth3_users(id)
		ON DELETE CASCADE,
	client_id INT,
	FOREIGN KEY (client_id)
		REFERENCES auth3_clients(id)
		ON DELETE CASCADE,
	authorization_code VARCHAR(80),
	is_revoked TINYINT(1) DEFAULT '0',
	expires TIMESTAMP 
		DEFAULT CURRENT_TIMESTAMP
		ON UPDATE CURRENT_TIMESTAMP,
	scopes VARCHAR(2048),
	UNIQUE (authorization_code),
	PRIMARY KEY (id)
) charset=utf8 ENGINE=INNODB;

CREATE TABLE auth3_scopes (
	id INT NOT NULL AUTO_INCREMENT,
	name varchar(80),
	is_default TINYINT(1) DEFAULT '0',
	PRIMARY KEY (id)
) charset=utf8 ENGINE=INNODB;

CREATE TABLE auth3_history (
	id INT NOT NULL AUTO_INCREMENT,
	namespace VARCHAR(24),
	action VARCHAR(24),
	user_id INT,
	detail VARCHAR(128),
	time TIMESTAMP
		DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id)
		REFERENCES auth3_users(id)
		ON DELETE CASCADE
		ON UPDATE CASCADE,
	PRIMARY KEY (id)
) charset=utf8 ENGINE=INNODB;

CREATE TABLE auth3_recovery_codes (
	id INT NOT NULL AUTO_INCREMENT,
	user_id INT,
	code CHAR(10),
	FOREIGN KEY (user_id)
		REFERENCES auth3_users(id)
		ON DELETE CASCADE,
	PRIMARY KEY (id)
) charset=utf8 ENGINE=INNODB;

CREATE TABLE auth3_password_reset (
	id INT NOT NULL AUTO_INCREMENT,
	user_id INT,
	code CHAR(40),
	expires TIMESTAMP,
	FOREIGN KEY (user_id)
		REFERENCES auth3_users(id)
		ON DELETE CASCADE,
	UNIQUE (user_id),
	UNIQUE (code),
	PRIMARY KEY (id)
) charset=utf8 ENGINE=INNODB;
