<?php
/**
 * DokuWiki Plugin authwordpress (Auth Component)
 *
 * Provides authentication against a WordPress MySQL database backend
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * See the COPYING file in your DokuWiki folder for details
 *
 * @author     Damien Regad <dregad@mantisbt.org>
 * @copyright  2015 Damien Regad
 * @license    GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @version    1.0
 * @link       https://github.com/dregad/dokuwiki-authwordpress
 */


// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

/**
 * WordPress password hashing framework
 */
require_once('class-phpass.php');

/**
 * Authentication class
 */
class auth_plugin_authwordpress extends DokuWiki_Auth_Plugin {

	/**
	 * SQL statement to retrieve User data from WordPress DB
	 * (including group memberships)
	 */
	const SQL_WP_USER_DATA = "SELECT
			id, user_login, user_pass, user_email, display_name,
			meta_value AS groups
		FROM wp_users u
		JOIN wp_usermeta m ON u.id = m.user_id
		WHERE meta_key = 'wp_capabilities'
		AND user_login = :user";

	/**
	 * Constructor.
	 */
	public function __construct() {
		parent::__construct();

		// Try to establish a connection to the WordPress DB
		// abort in case of failure
		try {
			$wp_db = $this->wp_connect();
		}
		catch (Exception $e) {
			msg(sprintf($this->getLang('error_connect_failed'), $e->getMessage()));
			$this->success = false;
			return;
		}

		$this->success = true;
	}


	/**
	 * Check user+password
	 *
	 * @param   string $user the user name
	 * @param   string $pass the clear text password
	 * @return  bool
	 *
	 * @uses PasswordHash::CheckPassword WordPress password hasher
	 */
	public function checkPass($user, $pass) {
		$data = $this->getUserData($user);
		if ($data === false) {
			return false;
		}

		$hasher = new PasswordHash(8, true);
		return $hasher->CheckPassword($pass, $data['pass']);
	}


	/**
	 * Returns info about the given user
	 *
	 * @param   string $user the user name
	 * @return  array containing user data or false
	 */
	function getUserData($user, $requireGroups=true) {
		global $conf;

		$wp_db = $this->wp_connect();
		$stmt = $wp_db->prepare(self::SQL_WP_USER_DATA);
		$stmt->bindParam(':user', $user);

		if (!$stmt->execute()) {
			// Query execution failed
			return false;
		}

		$user = $stmt->fetch(PDO::FETCH_ASSOC);
		if ($user === false) {
			// Unknown user
			return false;
		}

		// Group membership - add DokuWiki's default group
		$groups = array_keys(unserialize($user['groups']));
		$groups[] = $conf['defaultgroup'];

		$info = array(
			'user' => $user['user_login'],
			'name' => $user['display_name'],
			'pass' => $user['user_pass'],
			'mail' => $user['user_email'],
			'grps' => $groups,
		);
		return $info;
	}


	/**
	 * Connect to Wordpress database
	 *
	 * @return PDO object
	 */
	private function wp_connect() {
		$dsn = array(
			'host=' . $this->getConf('hostname'),
			'dbname=' . $this->getConf('database'),
		);
		$port = $this->getConf('port');
		if ($port) {
			$dsn[] = 'port=' . $port;
		}
		$dsn = 'mysql:' . implode(';', $dsn);

		return new PDO($dsn, $this->getConf('username'), $this->getConf('password'));
	}

}

// vim:ts=4:sw=4:noet:
