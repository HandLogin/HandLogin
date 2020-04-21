<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

/**
 * Authenticate API for user initialize.
 */
class Authenticate
{
    // API string
    public const API = "authenticate";

    // Column names
    private const COLUMN_NAME = "name";
    private const COLUMN_SALT = "salt";
    private const COLUMN_HASH = "hash";
    private const COLUMN_LOCK = "lock";

    // API mode
    private const TOKENS = true;

    // Configuration
    private static stdClass $configuration;

    // Base APIs
    private static Database $database;
    private static Authority $authority;

    /**
     * API initializer.
     * @param string $app App name
     */
    public static function initialize($app)
    {
        // Load configuration
        self::$configuration = new stdClass();
        self::$configuration->hooks = json_decode(file_get_contents(Utility::evaluateFile("hooks.json", self::API)));
        self::$configuration->locks = json_decode(file_get_contents(Utility::evaluateFile("locks.json", self::API)));
        self::$configuration->lengths = json_decode(file_get_contents(Utility::evaluateFile("lengths.json", self::API)));
        self::$configuration->permissions = json_decode(file_get_contents(Utility::evaluateFile("permissions.json", self::API)));
        // Make sure the database is initiated.
        self::$database = new Database(self::API . "_" . bin2hex($app));
        self::$database->createColumn(self::COLUMN_NAME);
        self::$database->createColumn(self::COLUMN_SALT);
        self::$database->createColumn(self::COLUMN_HASH);
        self::$database->createColumn(self::COLUMN_LOCK);
        // Make sure the authority is set-up
        self::$authority = new Authority(self::API . "_" . bin2hex($app));
    }

    /**
     * Main API hook.
     */
    public static function handle()
    {
        // Handle the request
        Base::handle(function ($action, $parameters) {
            if (isset($parameters->app)) {
                if (is_string($parameters->app)) {
                    // Make sure the name is longer the 0
                    if (strlen($parameters->app) > 0) {
                        Authenticate::initialize($parameters->app);
                        if (isset(self::$configuration->hooks->$action)) {
                            if (self::$configuration->hooks->$action === true) {
                                // Init as sub-API
                                if ($action === "validate") {
                                    if (isset($parameters->token)) {
                                        if (is_string($parameters->token)) {
                                            return self::validate($parameters->token);
                                        }
                                        return [false, "Invalid parameters"];
                                    }
                                    return [false, "Missing parameters"];
                                } else if ($action === "signIn") {
                                    // Authenticate the user using the password, return the new session
                                    if (isset($parameters->name) &&
                                        isset($parameters->password)) {
                                        if (is_string($parameters->name) &&
                                            is_string($parameters->password)) {
                                            return self::signIn($parameters->name, $parameters->password);
                                        }
                                        return [false, "Invalid parameters"];
                                    }
                                    return [false, "Missing parameters"];
                                } else if ($action === "signUp") {
                                    // Create a new user
                                    if (isset($parameters->name) &&
                                        isset($parameters->password)) {
                                        if (is_string($parameters->name) &&
                                            is_string($parameters->password)) {
                                            return self::signUp($parameters->name, $parameters->password);
                                        }
                                        return [false, "Invalid parameters"];
                                    }
                                    return [false, "Missing parameters"];
                                } else if ($action === "setValue") {
                                    if (isset($parameters->token) && isset($parameters->key) && isset($parameters->value)) {
                                        if (is_string($parameters->token) && is_string($parameters->key) && is_string($parameters->value)) {
                                            if (($userID = self::validate($parameters->token))[0]) {
                                                self::$database->createColumn($parameters->key);
                                                self::$database->set($userID[1], $parameters->key, $parameters->value);
                                                return [true, "Value set"];
                                            }
                                            return $userID;
                                        }
                                        return [false, "Invalid types"];
                                    }
                                    return [false, "Missing parameters"];
                                } else if ($action === "getValue") {
                                    if (isset($parameters->token) && isset($parameters->key)) {
                                        if (is_string($parameters->token) && is_string($parameters->key)) {
                                            if (($userID = self::validate($parameters->token))[0]) {
                                                self::$database->createColumn($parameters->key);
                                                return self::$database->get($userID[1], $parameters->key);
                                            }
                                            return $userID;
                                        }
                                        return [false, "Invalid types"];
                                    }
                                    return [false, "Missing parameters"];
                                } else if ($action === "getUsers") {
                                    if (isset($parameters->token)) {
                                        if (is_string($parameters->token)) {
                                            $userID = self::validate($parameters->token);
                                            if ($userID[0]) {
                                                if (isset($parameters->columns)) {
                                                    if (is_string($parameters->columns)) {
                                                        // Check admin
                                                        if (self::$database->get($userID[1], "isAdmin")[1] === "true") {
                                                            // Columns to read
                                                            $columns = json_decode($parameters->columns);
                                                            // List rows
                                                            $rows = array_slice(scandir(Utility::evaluateFile("rows", Database::API, self::API)), 2);
                                                            // Users array
                                                            $array = array();
                                                            foreach ($rows as $row) {
                                                                $user = new stdClass();
                                                                $user->id = $row;
                                                                foreach ($columns as $column) {
                                                                    $result = self::$database->get($row, $column);
                                                                    $user->$column = $result[1];
                                                                }
                                                                array_push($array, $user);
                                                            }
                                                            return [true, $array];
                                                        }
                                                        return [false, "User is not an admin"];
                                                    }
                                                    return [false, "Invalid parameters"];
                                                }
                                                return [false, "Missing parameters"];
                                            }
                                            return $userID;
                                        }
                                        return [false, "Invalid parameters"];
                                    }
                                    return [false, "Missing parameters"];
                                }
                                return [false, "Unhandled hook"];
                            }
                            return [false, "Locked hook"];
                        }
                        return [false, "Undefined hook"];
                    }
                    return [false, "App name too short"];
                }
                return [false, "Invalid app name"];
            }
            return [false, "Missing app name"];
        });
    }

    /**
     * Authenticate a user.
     * @param string $token Token
     * @return array Results
     */
    public static function validate($token)
    {
        if (self::TOKENS) {
            // Authenticate the user using tokens
            return self::$authority->validate($token, self::$configuration->permissions->validating);
        } else {
            // Authenticate the user using sessions
            return self::$database->hasLink($token);
        }
    }

    /**
     * Creates a new user.
     * @param string $name User Name
     * @param string $password User Password
     * @return array Results
     */
    public static function signUp($name, $password)
    {
        // Create user ID
        $userID = bin2hex($name);
        // Check for user existence
        if (!self::$database->hasRow($userID)[0]) {
            // Check password length
            if (strlen($password) >= self::$configuration->lengths->password) {
                // Generate a unique user id
                if (self::$database->createRow($userID)[0]) {
                    // Generate salt and hash
                    $salt = Utility::random(self::$configuration->lengths->salt);
                    $hash = Utility::hash($password . $salt);
                    // Set user information
                    self::$database->set($userID, self::COLUMN_NAME, $name);
                    self::$database->set($userID, self::COLUMN_SALT, $salt);
                    self::$database->set($userID, self::COLUMN_HASH, $hash);
                    self::$database->set($userID, self::COLUMN_LOCK, strval(0));
                    // Return a success result
                    return [true, $userID];
                }
                // Fallback result
                return [false, "User creation error"];
            }
            // Fallback result
            return [false, "Password too short"];
        }
        // Fallback result
        return [false, "User already exists"];
    }

    /**
     * Create a new user token.
     * @param string $name User Name
     * @param string $password User Password
     * @return array Result
     */
    public static function signIn($name, $password)
    {
        // Check if the user exists
        $userID = bin2hex($name);
        if (self::$database->hasRow($userID)[0]) {
            // Retrieve the lock value
            $lock = self::$database->get($userID, self::COLUMN_LOCK);
            if ($lock[0]) {
                // Verify that the user isn't locked
                if (intval($lock[1]) < time()) {
                    // Retrieve the salt and hash
                    $salt = self::$database->get($userID, self::COLUMN_SALT);
                    if ($salt[0]) {
                        $hash = self::$database->get($userID, self::COLUMN_HASH);
                        if ($hash[0]) {
                            // Check password match
                            if (Utility::hash($password . $salt[1]) === $hash[1]) {
                                // Correct credentials
                                if (self::TOKENS) {
                                    // Issue a new token
                                    return self::$authority->issue($userID, self::$configuration->permissions->issuing);
                                } else {
                                    // Create a new session
                                    return self::$database->createLink($userID, Utility::random(self::$configuration->lengths->session));
                                }
                            } else {
                                // Lock the user
                                self::$database->set($userID, self::COLUMN_LOCK, strval(time() + self::$configuration->locks->timeout));
                                // Return a failure result
                                return [false, "Wrong password"];
                            }
                        }
                        // Fallback result
                        return $hash;
                    }
                    // Fallback result
                    return $salt;
                }
                // Fallback result
                return [false, "User is locked"];
            }
            // Fallback result
            return $lock;
        }
        // Fallback result
        return [false, "User does not exist"];
    }
}

/**
 * Base API for handling requests.
 */
class Base
{
    // Constants
    public const API = "base";

    /**
     * Handles API calls by handing them over to the callback.
     * @param callable $callback Callback to handle the request
     */
    public static function handle($callback)
    {
        // Initialize the response
        $result = new stdClass();
        // Initialize the action
        if (count($_GET) > 0) {
            // Get the action
            $requestAction = array_key_first($_GET);
            // Parse the parameters
            $requestParameters = new stdClass();
            // Loop over GET parameters
            foreach ($_GET as $name => $value) {
                if (is_string($value))
                    $requestParameters->$name = $value;
            }
            // Loop over POST parameters
            foreach ($_POST as $name => $value) {
                if (is_string($value))
                    $requestParameters->$name = $value;
            }
            // Unset the action
            unset($requestParameters->$requestAction);
            // Execute the call
            $requestResult = $callback($requestAction, $requestParameters);
            // Parse the results
            if (is_array($requestResult)) {
                if (count($requestResult) === 2) {
                    if (is_bool($requestResult[0])) {
                        // Set status
                        $result->status = $requestResult[0];
                        // Set result
                        $result->result = $requestResult[1];
                    }
                }
            }
        }
        // Change the response type
        header("Content-Type: application/json");
        // Echo response
        echo json_encode($result);
    }
}

/**
 * Base API for utility functions.
 */
class Utility
{
    // Directory root
    private const DIRECTORY_ROOT = __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "files";

    // Directory delimiter
    private const DIRECTORY_DELIMITER = ":";

    // Hashing properties
    private const HASHING_ROUNDS = 16;
    private const HASHING_ALGORITHM = "sha256";

    /**
     * Returns a writable path for a name.
     * @param string $name Path name
     * @param string $base Base directory
     * @return string Path
     */
    public static function evaluatePath($name, $base = self::DIRECTORY_ROOT)
    {
        // Split name
        $split = explode(self::DIRECTORY_DELIMITER, $name, 2);
        // Check if we have to create a sub-path
        if (count($split) > 1) {
            // Append first path to the base
            $base = $base . DIRECTORY_SEPARATOR . $split[0];
            // Make sure the path exists
            if (!file_exists($base)) {
                mkdir($base);
            }
            // Return the path
            return self::evaluatePath($split[1], realpath($base));
        }
        // Return the last path
        return $base . DIRECTORY_SEPARATOR . $name;
    }

    /**
     * Returns a writable file path for a name.
     * @param string $name File name
     * @param string $hostAPI Host API
     * @param string $guestAPI Guest API
     * @return string File path
     */
    public static function evaluateFile($name = "", $hostAPI = Base::API, $guestAPI = null)
    {
        // Add APIs
        $name = implode(self::DIRECTORY_DELIMITER, [$hostAPI, $guestAPI, $name]);
        // Return the path
        return self::evaluatePath($name);
    }

    /**
     * Returns a writable directory path for a name.
     * @param string $name Directory name
     * @param string $hostAPI Host API
     * @param string $guestAPI Guest API
     * @return string Directory path
     */
    public static function evaluateDirectory($name = "", $hostAPI = Base::API, $guestAPI = null)
    {
        // Find parent directory
        $directory = self::evaluateFile($name, $hostAPI, $guestAPI);
        // Make sure the subdirectory exists
        if (!file_exists($directory)) mkdir($directory);
        // Return the directory path
        return $directory;
    }

    /**
     * Creates a random string.
     * @param int $length String length
     * @return string String
     */
    public static function random($length = 0)
    {
        if ($length > 0) {
            return str_shuffle("0123456789abcdefghijklmnopqrstuvwxyz")[0] . self::random($length - 1);
        }
        return "";
    }

    /**
     * Hashes a message.
     * @param string $message Message
     * @param int $rounds Number of rounds
     * @return string Hash
     */
    public static function hash($message, $rounds = self::HASHING_ROUNDS)
    {
        if ($rounds === 0) {
            return hash(self::HASHING_ALGORITHM, $message);
        }
        return hash(self::HASHING_ALGORITHM, self::hash($message, $rounds - 1));
    }

    /**
     * Signs a message.
     * @param string $message Message
     * @param string $secret Shared secret
     * @param int $rounds Number of rounds
     * @return string Signature
     */
    public static function sign($message, $secret, $rounds = self::HASHING_ROUNDS)
    {
        if ($rounds === 0) {
            return hash_hmac(self::HASHING_ALGORITHM, $message, $secret);
        }
        return hash_hmac(self::HASHING_ALGORITHM, self::sign($message, $secret, $rounds - 1), $secret);
    }
}

/**
 * Base API for storing user data.
 */
class Database
{
    // Constants
    public const API = "database";

    private const LENGTH = 32;
    private const SEPARATOR = "\n";

    // Guest API
    private string $API;

    /**
     * Database constructor.
     * @param string $API API name
     */
    public function __construct($API = Base::API)
    {
        $this->API = $API;
    }

    /**
     * Creates a new database row.
     * @param null $id ID
     * @return array Result
     */
    public function createRow($id = null)
    {
        // Generate a row ID
        if ($id === null) {
            $id = Utility::random(self::LENGTH);
        }
        // Check if the row already exists
        $has_row = $this->hasRow($id);
        if (!$has_row[0]) {
            // Create row directory
            mkdir(Utility::evaluateFile("rows:$id", self::API, $this->API));
            // Return result
            return [true, $id];
        }
        return [false, "Row already exists"];
    }

    /**
     * Creates a new database column.
     * @param string $name Column name
     * @return array Result
     */
    public function createColumn($name)
    {
        // Generate hashed string
        $hashed = Utility::hash($name);
        // Check if the column already exists
        $has_column = $this->hasColumn($name);
        if (!$has_column[0]) {
            // Create column directory
            mkdir(Utility::evaluateFile("columns:$hashed", self::API, $this->API));
            // Return result
            return [true, $name];
        }
        return [false, "Column already exists"];
    }

    /**
     * Creates a new database link.
     * @param string $row Row ID
     * @param string $link Link value
     * @return array Result
     */
    public function createLink($row, $link)
    {
        // Generate hashed string
        $hashed = Utility::hash($link);
        // Check if the link already exists
        $has_link = $this->hasLink($link);
        if (!$has_link[0]) {
            // Make sure the row exists
            $has_row = $this->hasRow($row);
            if ($has_row[0]) {
                // Generate link file
                file_put_contents(Utility::evaluateFile("links:$hashed", self::API, $this->API), $row);
                // Return result
                return [true, $link];
            }
            return $has_row;
        }
        return [false, "Link already exists"];
    }

    /**
     * Check whether a database row exists.
     * @param string $id Row ID
     * @return array Result
     */
    public function hasRow($id)
    {
        // Store path
        $path = Utility::evaluateFile("rows:$id", self::API, $this->API);
        // Check if path exists and is a directory
        if (file_exists($path) && is_dir($path)) {
            return [true, $id];
        }
        return [false, "Row doesn't exist"];
    }

    /**
     * Check whether a database column exists.
     * @param string $name Column name
     * @return array Result
     */
    public function hasColumn($name)
    {
        // Generate hashed string
        $hashed = Utility::hash($name);
        // Store path
        $path = Utility::evaluateFile("columns:$hashed", self::API, $this->API);
        // Check if path exists and is a directory
        if (file_exists($path) && is_dir($path)) {
            return [true, $name];
        }
        return [false, "Column doesn't exist"];
    }

    /**
     * Check whether a database link exists.
     * @param string $link Link value
     * @return array Result
     */
    public function hasLink($link)
    {
        // Generate hashed string
        $hashed = Utility::hash($link);
        // Store path
        $path = Utility::evaluateFile("links:$hashed", self::API, $this->API);
        // Check if path exists and is a file
        if (file_exists($path) && is_file($path)) {
            // Read link
            return [true, file_get_contents($path)];
        }
        return [false, "Link doesn't exist"];
    }

    /**
     * Check whether a database value exists.
     * @param string $row Row ID
     * @param string $column Column name
     * @return array Result
     */
    public function isset($row, $column)
    {
        // Check if row exists
        $has_row = $this->hasRow($row);
        if ($has_row[0]) {
            // Check if the column exists
            $has_column = $this->hasColumn($column);
            if ($has_column[0]) {
                // Generate hashed string
                $hashed_name = Utility::hash($column);
                // Store path
                $path = Utility::evaluateFile("rows:$row:$hashed_name", self::API, $this->API);
                // Check if path exists and is a file
                if (file_exists($path) && is_file($path)) {
                    return [true, null];
                }
                return [false, "Value doesn't exist"];
            }
            return $has_column;
        }
        return $has_row;
    }

    /**
     * Sets a database value.
     * @param string $row Row ID
     * @param string $column Column name
     * @param string $value Value
     * @return array Result
     */
    public function set($row, $column, $value)
    {
        // Remove previous values
        if ($this->isset($row, $column)[0]) {
            $this->unset($row, $column);
        }
        // Check if the column exists
        $has_column = $this->hasColumn($column);
        if ($has_column[0]) {
            // Create hashed string
            $hashed_name = Utility::hash($column);
            // Store path
            $value_path = Utility::evaluateFile("rows:$row:$hashed_name", self::API, $this->API);
            // Create hashed string
            $hashed_value = Utility::hash($value);
            // Write path
            file_put_contents($value_path, $value);
            // Store new path
            $index_path = Utility::evaluateFile("columns:$hashed_name:$hashed_value", self::API, $this->API);
            // Create rows array
            $rows = array();
            // Make sure the index file exists
            if (file_exists($index_path) && is_file($index_path)) {
                // Read contents
                $contents = file_get_contents($index_path);
                // Separate lines
                $rows = explode(self::SEPARATOR, $contents);
            }
            // Insert row to rows
            array_push($rows, $row);
            // Write contents
            file_put_contents($index_path, implode(self::SEPARATOR, $rows));
            // Result result
            return [true, null];
        }
        return $has_column;
    }

    /**
     * Unsets a database value.
     * @param string $row Row ID
     * @param string $column Column name
     * @return array Result
     */
    public function unset($row, $column)
    {
        // Check if a value is already set
        $isset = $this->isset($row, $column);
        if ($isset[0]) {
            // Check if the column exists
            $has_column = $this->hasColumn($column);
            if ($has_column[0]) {
                // Create hashed string
                $hashed_name = Utility::hash($column);
                // Store path
                $value_path = Utility::evaluateFile("rows:$row:$hashed_name", self::API, $this->API);
                // Get value & Hash it
                $value = file_get_contents($value_path);
                // Create hashed value
                $hashed_value = Utility::hash($value);
                // Remove path
                unlink($value_path);
                // Store new path
                $index_path = Utility::evaluateFile("columns:$hashed_name:$hashed_value", self::API, $this->API);
                // Make sure the index file exists
                if (file_exists($index_path) && is_file($index_path)) {
                    // Read contents
                    $contents = file_get_contents($index_path);
                    // Separate lines
                    $rows = explode(self::SEPARATOR, $contents);
                    // Remove row from rows
                    unset($rows[array_search($row, $rows)]);
                    // Write contents
                    file_put_contents($index_path, implode(self::SEPARATOR, $rows));
                    // Return result
                    return [true, null];
                }
                return [false, "Index doesn't exist"];
            }
            return $has_column;
        }
        return $isset;
    }

    /**
     * Gets a database value.
     * @param string $row Row ID
     * @param string $column Column name
     * @return array Result
     */
    public function get($row, $column)
    {
        // Check if a value is set
        $isset = $this->isset($row, $column);
        if ($isset[0]) {
            // Generate hashed string
            $hashed_name = Utility::hash($column);
            // Store path
            $path = Utility::evaluateFile("rows:$row:$hashed_name", self::API, $this->API);
            // Read path
            return [true, file_get_contents($path)];
        }
        return $isset;
    }

    /**
     * Searches rows by column values.
     * @param string $column Column name
     * @param string $value Value
     * @return array Matching rows
     */
    public function search($column, $value)
    {
        // Create rows array
        $rows = array();
        // Check if the column exists
        $has_column = $this->hasColumn($column);
        if ($has_column[0]) {
            // Create hashed string
            $hashed_name = Utility::hash($column);
            // Create hashed string
            $hashed_value = Utility::hash($value);
            // Store new path
            $index_path = Utility::evaluateFile("columns:$hashed_name:$hashed_value", self::API, $this->API);
            // Make sure the index file exists
            if (file_exists($index_path) && is_file($index_path)) {
                // Read contents
                $contents = file_get_contents($index_path);
                // Separate lines
                $rows = explode(self::SEPARATOR, $contents);
            }
            return [true, $rows];
        }
        return $has_column;
    }
}

/**
 * Base API for issuing and validating tokens.
 */
class Authority
{
    // Constants
    public const API = "authority";

    private const LENGTH = 512;
    private const SEPARATOR = ":";
    private const VALIDITY = 31 * 24 * 60 * 60;

    // Guest API
    private string $API;

    // Secret string
    private string $secret;

    /**
     * Authority constructor.
     * @param string $API API name
     */
    public function __construct($API = Base::API)
    {
        $this->API = $API;
        // Create secret
        $path = Utility::evaluateFile("secret.key", self::API, $this->API);
        // Check existence
        if (!file_exists($path)) {
            // Create the secret file
            file_put_contents($path, Utility::random(self::LENGTH));
        }
        // Read secret
        $this->secret = file_get_contents($path);
    }

    /**
     * Creates a token.
     * @param string | stdClass | array $contents Content
     * @param array $permissions Permissions
     * @param float | int $validity Validity time
     * @return array Result
     */
    public function issue($contents, $permissions = [], $validity = self::VALIDITY)
    {
        // Create token object
        $token_object = new stdClass();
        $token_object->contents = $contents;
        $token_object->permissions = $permissions;
        $token_object->issuer = Utility::hash($this->API);
        $token_object->expiry = time() + intval($validity);
        // Create token string
        $token_object_string = bin2hex(json_encode($token_object));
        // Calculate signature
        $token_signature = Utility::sign($token_object_string, $this->secret);
        // Create parts
        $token_parts = [$token_object_string, $token_signature];
        // Combine all into token
        $token = implode(self::SEPARATOR, $token_parts);
        // Return combined message
        return [true, $token];
    }

    /**
     * Validates a token.
     * @param string $token Token
     * @param array $permissions Permissions
     * @return array Validation result
     */
    public function validate($token, $permissions = [])
    {
        // Try parsing
        // Separate string
        $token_parts = explode(self::SEPARATOR, $token);
        // Validate content count
        if (count($token_parts) === 2) {
            // Store parts
            $token_object_string = $token_parts[0];
            $token_signature = $token_parts[1];
            // Validate signature
            if (Utility::sign($token_object_string, $this->secret) === $token_signature) {
                // Parse token object
                $token_object = json_decode(hex2bin($token_object_string));
                // Validate existence
                if (isset($token_object->contents) && isset($token_object->permissions) && isset($token_object->issuer) && isset($token_object->expiry)) {
                    // Validate issuer
                    if ($token_object->issuer === Utility::hash($this->API)) {
                        // Validate expiry
                        if (time() < $token_object->expiry) {
                            // Validate permissions
                            foreach ($permissions as $permission) {
                                // Make sure permission exists
                                if (array_search($permission, $token_object->permissions) === false) {
                                    // Fallback error
                                    return [false, "Insufficient token permissions"];
                                }
                            }
                            // Return token
                            return [true, $token_object->contents];
                        }
                        // Fallback error
                        return [false, "Invalid token expiry"];
                    }
                    // Fallback error
                    return [false, "Invalid token issuer"];
                }
                // Fallback error
                return [false, "Invalid token structure"];
            }
            // Fallback error
            return [false, "Invalid token signature"];
        }
        // Fallback error
        return [false, "Invalid token format"];
    }
}