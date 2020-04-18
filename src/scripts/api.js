/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

let token = localStorage.getItem("token");

function signOut() {
    localStorage.removeItem("token");
}

// Checks if user is signed in
function validate(tag = null) {
    call("validate", {
        app: APP_NAME,
        token: token
    }, tag, (success, result) => {
        if (success) {
            console.log("Validate - " + success);
        }
    });
}

// Create user
function signUp(name, password, tag = null) {
    call("signUp", {
        app: APP_NAME,
        name: name,
        password: password
    }, tag, (success, result) => {
        if (success) {
            console.log("Sign up - " + name + ": " + success);
        }
    });
}

// Log-in
function signIn(name, password, tag = null) {
    call("signIn", {
        app: APP_NAME,
        name: name,
        password: password
    }, tag, (success, result) => {
        localStorage.setItem("token", token = result);
        if (success) {
            console.log("Sign in - " + name + ": " + success);
        }
    });
}

// Writes data to the user's database
function setData(dataName, dataValue, tag = null) {
    call("setValue", {
        app: APP_NAME,
        key: dataName,
        value: dataValue,
        token: token
    }, tag, (success, result) => {
        if (success) {
            console.log("Set data - " + dataName + ": " + dataValue);
        }
    });
}

// Reads data from the user's database
function getData(dataName, tag = null) {
    call("getValue", {
        app: APP_NAME,
        key: dataName,
        token: token
    }, tag, (success, result) => {
        if (success) {
            console.log("Get data - " + dataName + ": " + result);
        }
    });
}

// Don't touch

// Sends a message to the server
function call(action = null, parameters = null, tag = null, callback = null) {
    // Create the query
    let query = "";
    for (let key in parameters) {
        query += "&";
        query += key;
        query += "=";
        query += encodeURIComponent(parameters[key]);
    }
    // Final URL
    let url = "http://handlogin.herokuapp.com/api/?" + action + query;
    // Log
    console.log("Sending request: " + url);
    // Perform the request
    fetch(url).then(response => response.json().then(result => {
        // Check the result's integrity
        if (result.hasOwnProperty("status") && result.hasOwnProperty("result")) {
            // Call the callback with the result
            if (callback !== undefined && callback !== null) {
                callback(result["status"], result["result"]);
            }
            // Call result-here
            if (resultHere !== undefined && resultHere !== null) {
                resultHere(tag, result["status"], result["result"]);
            }
        }
    }));
}