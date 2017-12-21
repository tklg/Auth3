CREATE TABLE auth3_users (
	id INT NOT NULL AUTO_INCREMENT,
	email VARCHAR(128),
	password VARCHAR(255),
	first_name VARCHAR(128),
	family_name VARCHAR(128),
	#g_authcode VARCHAR(64),
	twofactor VARCHAR(16) DEFAULT NULL,		# contains g_authcode if yes, else nothing
	verification_status VARCHAR(40) DEFAULT 'false',
	join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id)
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
	is_revoked TINYINT(1) DEFAULT 0,
	expires TIMESTAMP 
		DEFAULT CURRENT_TIMESTAMP
		ON UPDATE CURRENT_TIMESTAMP,
	UNIQUE (access_token),
	PRIMARY KEY (id)
) charset=utf8 ENGINE=INNODB;

CREATE TABLE auth3_refresh_tokens (
	id INT NOT NULL AUTO_INCREMENT,
	/*user_id INT,
	FOREIGN KEY (user_id)
		REFERENCES auth3_users(id)
		ON DELETE CASCADE,
	client_id INT,
	FOREIGN KEY (client_id)
		REFERENCES auth3_clients(id)
		ON DELETE CASCADE,*/
	refresh_token VARCHAR(128),
	access_token VARCHAR(128),
	refresh_token_raw VARCHAR(512),
	#scopes VARCHAR(2048),
	is_revoked TINYINT(1) DEFAULT 0,
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
	authorization_code VARCHAR(40),
	is_revoked TINYINT(1) DEFAULT 0,
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
	is_default TINYINT(1) DEFAULT 0,
	PRIMARY KEY (id)
) charset=utf8 ENGINE=INNODB;

-- CREATE TABLE auth3_map_scopes_to_tokens (
-- 	id INT NOT NULL AUTO_INCREMENT,
-- 	scope_id INT,
-- 	FOREIGN KEY (scope_id)
-- 		REFERENCES auth3_scopes(id)
-- 		ON DELETE CASCADE,
-- 	access_token_id INT,
-- 	FOREIGN KEY (access_token_id)
-- 		REFERENCES auth3_access_tokens(id)
-- 		ON DELETE CASCADE,
-- 	refresh_token_id INT,
-- 	FOREIGN KEY (refresh_token_id)
-- 		REFERENCES auth3_refresh_tokens(id)
-- 		ON DELETE CASCADE,
-- 	PRIMARY KEY (id)
-- ) charset=utf8 ENGINE=INNODB;
