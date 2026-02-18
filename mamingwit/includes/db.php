<?php
// ============================================================
// MAMINGWIT CHECKER - Database Configuration
// ============================================================

define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'mamingwit_db');
define('DB_PORT', 3306);

class Database {
    private static $instance = null;
    private $connection;

    private function __construct() {
        $this->connection = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
        if ($this->connection->connect_error) {
            die(json_encode([
                'error' => true,
                'message' => 'Database connection failed. Please ensure XAMPP MySQL is running and the database is set up. Error: ' . $this->connection->connect_error
            ]));
        }
        $this->connection->set_charset('utf8mb4');
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new Database();
        }
        return self::$instance;
    }

    public function getConnection() {
        return $this->connection;
    }

    public function query($sql) {
        $result = $this->connection->query($sql);
        if ($this->connection->error) {
            error_log('DB Error: ' . $this->connection->error . ' | SQL: ' . $sql);
        }
        return $result;
    }

    public function prepare($sql) {
        return $this->connection->prepare($sql);
    }

    public function escape($value) {
        return $this->connection->real_escape_string($value);
    }

    public function getLastId() {
        return $this->connection->insert_id;
    }

    public function getAffectedRows() {
        return $this->connection->affected_rows;
    }
}
?>