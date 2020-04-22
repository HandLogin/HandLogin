/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

let token = localStorage.getItem("token");

function signOut() {
    localStorage.removeItem("token");
}

// Checks if user is signed in
function validate(callback = null) {
    call("validate", {
        app: APP_NAME,
        token: token
    }, callback, (success, result) => {
        if (success) {
            console.log("Validate - " + success);
        }
    });
}

// Create user
function signUp(name, password, callback = null) {
    call("signUp", {
        app: APP_NAME,
        name: name,
        password: password
    }, callback, (success, result) => {
        if (success) {
            console.log("Sign up - " + name + ": " + success);
        }
    });
}

// Log-in
function signIn(name, password, callback = null) {
    call("signIn", {
        app: APP_NAME,
        name: name,
        password: password
    }, callback, (success, result) => {
        localStorage.setItem("token", token = result);
        if (success) {
            console.log("Sign in - " + name + ": " + success);
        }
    });
}

// Writes data to the user's database
function setData(dataName, dataValue, callback = null) {
    call("setValue", {
        app: APP_NAME,
        key: dataName,
        value: dataValue,
        token: token
    }, callback, (success, result) => {
        if (success) {
            console.log("Set data - " + dataName + ": " + dataValue);
        }
    });
}

// Reads data from the user's database
function getData(dataName, callback = null) {
    call("getValue", {
        app: APP_NAME,
        key: dataName,
        token: token
    }, callback, (success, result) => {
        if (success) {
            console.log("Get data - " + dataName + ": " + result);
        }
    });
}

function setImage(name, input, callback = null) {
    let file = input.files[0];
    let fileReader = new FileReader();
    fileReader.addEventListener("load", function () {
        // reader.result
        setData("image_" + name, fileReader.result, callback);
    }, false);
    fileReader.readAsDataURL(file);
}

function getImage(name, callback = null) {
    getData("image_" + name, callback);
}

function getUsers(columns = [], callback = null) {
    call("getUsers", {
        app: APP_NAME,
        token: token
    }, callback, (success, result) => {
        if (success) {
            console.log("Get users - ");
            for (let user of result) {
                for (let column of columns) {
                    console.log(user.id + " - " + column + " - " + user[column]);
                }
            }
        }
    });
}

// Don't touch

// Sends a message to the server
function call(action = null, parameters = null, externalCallback = null, internalCallback = null) {
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
            // Call result-here or the passable callback
            if (internalCallback !== undefined && internalCallback !== null) {
                internalCallback(result["status"], result["result"]);
            }
            // Call the callback with the result
            if (externalCallback !== undefined && externalCallback !== null) {
                externalCallback(result["status"], result["result"]);
            }
        }
    }));
}