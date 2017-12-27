/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

-- Dump of table scopes
------------------------------------------------------------

DROP TABLE IF EXISTS `scopes`;

CREATE TABLE `scopes` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `identifier`  VARCHAR(128) NOT NULL,
  `description` VARCHAR(255) NULL,
  `created_at`  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Dump of table grants
------------------------------------------------------------

DROP TABLE IF EXISTS `grants`;

CREATE TABLE `grants` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `identifier`  VARCHAR(128) NOT NULL,
  `description` VARCHAR(255) NULL,
  `created_at`  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Dump of table grant_scopes
------------------------------------------------------------

DROP TABLE IF EXISTS `grant_scopes`;

CREATE TABLE `grant_scopes` (
  `grant_id` BIGINT UNSIGNED NOT NULL,
  `scope_id` BIGINT UNSIGNED NOT NULL,

  PRIMARY KEY (`grant_id`, `scope_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Dump of table clients
------------------------------------------------------------

DROP TABLE IF EXISTS `clients`;

CREATE TABLE `clients` (
  `id`           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name`         VARCHAR(128) NOT NULL,
  `identifier`   VARCHAR(128) NOT NULL,
  `secret`       VARCHAR(128) NOT NULL,
  `redirect_uri` VARCHAR(255) NOT NULL,
  `status`       TINYINT(1) UNSIGNED NOT NULL DEFAULT '1', -- Active
  `created_at`   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (`id`),
  KEY `identifier` (`identifier`),
  KEY `secret` (`secret`),
  KEY `status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Dump of table client_scopes
------------------------------------------------------------

DROP TABLE IF EXISTS `client_scopes`;

CREATE TABLE `client_scopes` (
  `client_id`  BIGINT UNSIGNED NOT NULL,
  `scope_id`   BIGINT UNSIGNED NOT NULL,

  PRIMARY KEY (`client_id`, `scope_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Dump of table client_grants
------------------------------------------------------------

DROP TABLE IF EXISTS `client_grants`;

CREATE TABLE `client_grants` (
  `client_id` BIGINT UNSIGNED NOT NULL,
  `grant_id`  BIGINT UNSIGNED NOT NULL,

  PRIMARY KEY (`client_id`, `grant_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Dump of table users
--------------------------------------------------------------

DROP TABLE IF EXISTS `users`;

CREATE TABLE `users` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name`       VARCHAR(80) NOT NULL,
  `email`      VARCHAR(128) NOT NULL,
  `password`   VARCHAR(255) NOT NULL,
  `status`     TINYINT(1) UNSIGNED NOT NULL DEFAULT '3',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Dump of table user_grants
------------------------------------------------------------

DROP TABLE IF EXISTS `user_grants`;

CREATE TABLE `user_grants` (
  `user_id`  BIGINT UNSIGNED NOT NULL,
  `grant_id` BIGINT UNSIGNED NOT NULL,

  PRIMARY KEY (`user_id`, `grant_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Dump of table user_scopes
------------------------------------------------------------

DROP TABLE IF EXISTS `user_scopes`;

CREATE TABLE `user_scopes` (
  `user_id` BIGINT UNSIGNED NOT NULL,
  `scope_id` BIGINT UNSIGNED NOT NULL,

  PRIMARY KEY (`user_id`, `scope_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- Dump of table user_clients
------------------------------------------------------------

DROP TABLE IF EXISTS `user_clients`;

CREATE TABLE `user_clients` (
  `user_id`   BIGINT UNSIGNED NOT NULL,
  `client_id` BIGINT UNSIGNED NOT NULL,

  PRIMARY KEY (`user_id`, `client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Dump of table access_tokens
------------------------------------------------------------

DROP TABLE IF EXISTS `access_tokens`;

CREATE TABLE `access_tokens` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `identifier` VARCHAR(128) NOT NULL,
  `client_id`  BIGINT UNSIGNED NOT NULL,
  `user_id`    BIGINT UNSIGNED NOT NULL,
  `expiration` TIMESTAMP NULL DEFAULT NULL,
  `revoked`    TINYINT(1) UNSIGNED NOT NULL DEFAULT '0',
  `type`       TINYINT UNSIGNED NOT NULL DEFAULT '1',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (`id`),
  KEY `client_id` (`client_id`),
  KEY `user_id` (`user_id`),
  KEY `revoked` (`revoked`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Dump of table access_token_scopes
------------------------------------------------------------

DROP TABLE IF EXISTS `access_token_scopes`;

CREATE TABLE `access_token_scopes` (
  `access_token_id` BIGINT UNSIGNED NOT NULL,
  `scope_id`        BIGINT UNSIGNED NOT NULL,

  PRIMARY KEY (`access_token_id`, `scope_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Dump of table refresh_tokens
------------------------------------------------------------

DROP TABLE IF EXISTS `refresh_tokens`;

CREATE TABLE `refresh_tokens` (
  `id`              BIGINT UNSIGNED NOT NULL,
  `identifier`      VARCHAR(128) NOT NULL,
  `access_token_id` BIGINT UNSIGNED NOT NULL,
  `expiration`      TIMESTAMP NULL DEFAULT NULL,
  `revoked`         TINYINT(1) NOT NULL DEFAULT '0',
  `created_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (`id`),
  KEY `access_token_id` (`access_token_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Dump of table auth_codes
------------------------------------------------------------

DROP TABLE IF EXISTS `auth_codes`;

CREATE TABLE `auth_codes` (
  `id`           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `identifier`   VARCHAR(128) NOT NULL,
  `user_id`      BIGINT UNSIGNED NOT NULL,
  `client_id`    BIGINT UNSIGNED NOT NULL,
  `expiration`   TIMESTAMP NULL DEFAULT NULL,
  `redirect_uri` VARCHAR(255) NOT NULL,
  `revoked`      TINYINT(1) NOT NULL DEFAULT '0',
  `created_at`   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `client_id` (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Dump of table auth_code_scopes
------------------------------------------------------------

DROP TABLE IF EXISTS `auth_code_scopes`;

CREATE TABLE `auth_code_scopes` (
  `auth_code_id` BIGINT UNSIGNED NOT NULL,
  `scope_id`     BIGINT UNSIGNED NOT NULL,

  PRIMARY KEY (`auth_code_id`, `scope_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;