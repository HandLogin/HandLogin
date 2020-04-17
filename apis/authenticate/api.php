<?php

/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

// Include Base API
include_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "base" . DIRECTORY_SEPARATOR . "api.php";

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
            if (isset(self::$configuration->hooks->$action)) {
                if (self::$configuration->hooks->$action === true) {
                    if (isset($parameters->app)) {
                        if (is_string($parameters->app)) {
                            // Make sure the name is longer the 0
                            if (strlen($parameters->app) > 0) {
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
                                }
                                return [false, "Unhandled hook"];
                            }
                            return [false, "App name too short"];
                        }
                        return [false, "Invalid app name"];
                    }
                    return [false, "Missing app name"];
                }
                return [false, "Locked hook"];
            }
            return [false, "Undefined hook"];
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