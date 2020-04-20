/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

let token = localStorage.getItem("token");

function signOut() {
    localStorage.removeItem("token");
}

// Checks if user is signed in
function validate(passable = null) {
    call("validate", {
        app: APP_NAME,
        token: token
    }, passable, (success, result) => {
        if (success) {
            console.log("Validate - " + success);
        }
    });
}

// Create user
function signUp(name, password, passable = null) {
    call("signUp", {
        app: APP_NAME,
        name: name,
        password: password
    }, passable, (success, result) => {
        if (success) {
            console.log("Sign up - " + name + ": " + success);
        }
    });
}

// Log-in
function signIn(name, password, passable = null) {
    call("signIn", {
        app: APP_NAME,
        name: name,
        password: password
    }, passable, (success, result) => {
        localStorage.setItem("token", token = result);
        if (success) {
            console.log("Sign in - " + name + ": " + success);
        }
    });
}

// Writes data to the user's database
function setData(dataName, dataValue, passable = null) {
    call("setValue", {
        app: APP_NAME,
        key: dataName,
        value: dataValue,
        token: token
    }, passable, (success, result) => {
        if (success) {
            console.log("Set data - " + dataName + ": " + dataValue);
        }
    });
}

// Reads data from the user's database
function getData(dataName, passable = null) {
    call("getValue", {
        app: APP_NAME,
        key: dataName,
        token: token
    }, passable, (success, result) => {
        if (success) {
            console.log("Get data - " + dataName + ": " + result);
        }
    });
}

// Don't touch

// Sends a message to the server
function call(action = null, parameters = null, passable = null, callback = null) {
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
            // Call result-here or the passable callback
            if (passable !== undefined && passable !== null) {
                if ((typeof passable).toLowerCase() === typeof "function") {
                    passable(result["status"], result["result"]);
                }else{
                    if (resultHere !== undefined && resultHere !== null) {
                        resultHere(passable, result["status"], result["result"]);
                    }
                }
            }
        }
    }));
}