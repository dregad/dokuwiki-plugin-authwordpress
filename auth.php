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
 * @version    1.1
 * @link       https://github.com/dregad/dokuwiki-authwordpress
 */


// must be run within Dokuwiki
if (!defined('DOKU_INC')) {
    die();
}

/**
 * WordPress password hashing framework
 */
require_once('class-phpass.php');

/**
 * Authentication class
 */
// @codingStandardsIgnoreLine
class auth_plugin_authwordpress extends DokuWiki_Auth_Plugin
{

    /**
     * SQL statement to retrieve User data from WordPress DB
     * (including group memberships)
     * '%prefix%' will be replaced by the actual prefix (from plugin config)
     * @var string $sql_wp_user_data
     */
    protected $sql_wp_user_data = "SELECT
            id, user_login, user_pass, user_email, display_name,
            meta_value AS grps
        FROM %prefix%users u
        JOIN %prefix%usermeta m ON u.id = m.user_id AND meta_key = '%prefix%capabilities'";

    /**
     * Wordpress database connection
     * @var PDO $db
     */
    protected $db;

    /**
     * Users cache
     * @var array $users
     */
    protected $users;

    /**
     * True if all users have been loaded in the cache
     * @see $users
     * @var bool $usersCached
     */
    protected $usersCached = false;

    /**
     * Filter pattern
     * @var array $filter
     */
    protected $filter;

    /**
     * Constructor.
     */
    public function __construct()
    {
        parent::__construct();

        // Plugin capabilities
        $this->cando['getUsers'] = true;
        $this->cando['getUserCount'] = true;

        // Try to establish a connection to the WordPress DB
        // abort in case of failure
        try {
            $this->connectWordpressDb();
        } catch (Exception $e) {
            msg(sprintf($this->getLang('error_connect_failed'), $e->getMessage()));
            $this->success = false;
            return;
        }

        // Initialize SQL query with configured prefix
        $this->sql_wp_user_data = str_replace(
            '%prefix%',
            $this->getConf('prefix'),
            $this->sql_wp_user_data
        );

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
    public function checkPass($user, $pass)
    {
        $data = $this->getUserData($user);
        if ($data === false) {
            return false;
        }

        $hasher = new PasswordHash(8, true);
        $check = $hasher->CheckPassword($pass, $data['pass']);
        dbglog("Password " . ($check ? 'OK' : 'Invalid'));

        return $check;
    }

    /**
     * Bulk retrieval of user data
     *
     * @param   int   $start index of first user to be returned
     * @param   int   $limit max number of users to be returned
     * @param   array $filter array of field/pattern pairs
     * @return  array userinfo (refer getUserData for internal userinfo details)
     */
    public function retrieveUsers($start = 0, $limit = 0, $filter = array())
    {
        msg($this->getLang('user_list_use_wordpress'));

        $this->cacheAllUsers();

        // Apply filter and pagination
        $this->setFilter($filter);
        $list = array();
        $count = $i = 0;
        foreach ($this->users as $user => $info) {
            if ($this->applyFilter($user, $info)) {
                if ($i >= $start) {
                    $list[$user] = $info;
                    $count++;
                    if ($limit > 0 && $count >= $limit) {
                        break;
                    }
                }
                $i++;
            }
        }

        return $list;
    }

    /**
     * Return a count of the number of user which meet $filter criteria
     *
     * @param array $filter
     * @return int
     */
    public function getUserCount($filter = array())
    {
        $this->cacheAllUsers();

        if (empty($filter)) {
            $count = count($this->users);
        } else {
            $this->setFilter($filter);
            $count = 0;
            foreach ($this->users as $user => $info) {
                $count += (int)$this->applyFilter($user, $info);
            }
        }
        return $count;
    }


    /**
     * Returns info about the given user
     *
     * @param string $user the user name
     * @param bool   $requireGroups defaults to true
     * @return array|false containing user data or false in case of error
     */
    public function getUserData($user, $requireGroups = true)
    {
        if (isset($this->users[$user])) {
            return $this->users[$user];
        }

        $sql = $this->sql_wp_user_data
            . 'WHERE user_login = :user';

        $stmt = $this->db->prepare($sql);
        $stmt->bindParam(':user', $user);
        dbglog("Retrieving data for user '$user'\n$sql");

        if (!$stmt->execute()) {
            // Query execution failed
            $err = $stmt->errorInfo();
            dbglog("Error $err[1]: $err[2]");
            return false;
        }

        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user === false) {
            // Unknown user
            dbglog("Unknown user");
            return false;
        }

        return $this->cacheUser($user);
    }


    /**
     * Connect to Wordpress database
     * Initializes $db property as PDO object
     */
    protected function connectWordpressDb()
    {
        if ($this->db) {
            // Already connected
            return;
        }

        // Build connection string
        $dsn = array(
            'host=' . $this->getConf('hostname'),
            'dbname=' . $this->getConf('database'),
            'charset=UTF8',
        );
        $port = $this->getConf('port');
        if ($port) {
            $dsn[] = 'port=' . $port;
        }
        $dsn = 'mysql:' . implode(';', $dsn);

        $this->db = new PDO($dsn, $this->getConf('username'), $this->getConf('password'));
    }

    /**
     * Convert a Wordpress DB User row to DokuWiki user info array
     * and stores it in the users cache
     *
     * @param  array $row Raw Wordpress user table row
     * @return array user data
     */
    protected function cacheUser($row)
    {
        global $conf;

        $login = $row['user_login'];

        // If the user is already cached, just return it
        if (isset($this->users[$login])) {
            return $this->users[$login];
        }

        // Group membership - add DokuWiki's default group
        $groups = array_keys(unserialize($row['grps']));
        if ($this->getConf('usedefaultgroup')) {
            $groups[] = $conf['defaultgroup'];
        }

        $info = array(
            'user' => $login,
            'name' => $row['display_name'],
            'pass' => $row['user_pass'],
            'mail' => $row['user_email'],
            'grps' => $groups,
        );

        $this->users[$login] = $info;
        return $info;
    }

    /**
     * Loads all Wordpress users into the cache
     *
     * @return void
     */
    protected function cacheAllUsers()
    {
        if ($this->usersCached) {
            return;
        }

        $stmt = $this->db->prepare($this->sql_wp_user_data);
        $stmt->execute();

        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $user) {
            $this->cacheUser($user);
        }

        $this->usersCached = true;
    }

    /**
     * Build filter patterns from given criteria
     *
     * @param array $filter
     */
    protected function setFilter($filter)
    {
        $this->filter = array();
        foreach ($filter as $field => $value) {
            // Build PCRE pattern, utf8 + case insensitive
            $this->filter[$field] = '/' . str_replace('/', '\/', $value) . '/ui';
        }
    }

    /**
     * Return true if given user matches filter pattern, false otherwise
     *
     * @param string $user login
     * @param array  $info User data
     * @return bool
     */
    protected function applyFilter($user, $info)
    {
        foreach ($this->filter as $elem => $pattern) {
            if ($elem == 'grps') {
                if (!preg_grep($pattern, $info['grps'])) {
                    return false;
                }
            } else {
                if (!preg_match($pattern, $info[$elem])) {
                    return false;
                }
            }
        }
        return true;
    }
}

// vim:ts=4:sw=4:noet:
