SET foreign_key_checks = 0;

DROP TABLE auth3_users;
DROP TABLE auth3_clients;
DROP TABLE auth3_access_tokens;
DROP TABLE auth3_refresh_tokens;
DROP TABLE auth3_authorization_codes;
DROP TABLE auth3_scopes;
-- DROP TABLE auth3_map_scopes_to_tokens;
-- DROP TABLE auth3_map_scopes_to_clients;

SET foreign_key_checks = 1;