INSERT INTO auth3_users (
	id, email, password, first_name, family_name
) VALUES (
	1,
	'test@test.test',
	'replace with hashed password',
	'Test',
	'Account'
);

INSERT INTO auth3_clients (
	client_name, client_display, client_secret, redirect_uri, grant_types, user_id
) VALUES (
	'testclient',
	'Test Client',
	'1',
	'localhost/auth3/src/public/auth_redirect',
	'client_credentials,password,authorization_code,implicit,refresh_token',
	1
);

INSERT INTO auth3_scopes (
	id, name, is_default
) VALUES (
	1,
	'test',
	1
);
