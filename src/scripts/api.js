/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

let token = localStorage.getItem("token");

function signOut() {
    localStorage.removeItem("token");
}

async function validate() {
    return await call("validate", {
        app: APP_NAME,
        token: token
    }) === null;
}

async function signUp(name, password) {
    return call("signUp", {
        app: APP_NAME,
        name: name,
        password: password
    });
}

async function signIn(name, password) {
    localStorage.setItem("token", token = await call("signIn", {
        app: APP_NAME,
        name: name,
        password: password
    }));
    return token;
}

async function setData(dataName, dataValue) {
    return call("setValue", {
        app: APP_NAME,
        key: dataName,
        value: dataValue,
        token: token
    });
}

async function getData(dataName) {
    return call("getValue", {
        app: APP_NAME,
        key: dataName,
        token: token
    });
}

// Don't touch

async function call(action = null, parameters = null, callback = null) {
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
    let response = await fetch(url);
    let result = await response.text();
    // Try to parse the result as JSON
    try {
        let API = JSON.parse(result);
        // Check the result's integrity
        if (API.hasOwnProperty("status") && API.hasOwnProperty("result")) {
            // Call the callback with the result
            return API["result"];
        } else {
            // Call the callback with an error
            return "API response malformed";
        }
    } catch (ignored) {
    }
    return "Error (Unknown)";
}