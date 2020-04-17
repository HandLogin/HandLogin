/**
 * Copyright (c) 2019 Nadav Tasher
 * https://github.com/NadavTasher/AuthenticationTemplate/
 **/

let token = localStorage.getItem("token");

function validate() {
    return call("signUp", {
        app: APP_NAME,
        token: token
    }) === null;
}

function signUp(name, password) {
    return call("signUp", {
        app: APP_NAME,
        name: name,
        password: password
    });
}

function signIn(name, password) {
    localStorage.setItem("token", token = call("signIn", {
        app: APP_NAME,
        name: name,
        password: password
    }));
    return token;
}

function signOut() {
    localStorage.removeItem("token");
}

function setData(dataName, dataValue) {
    return call("setValue", {
        app: APP_NAME,
        key: dataName,
        value: dataValue,
        token: token
    });
}

function getData(dataName) {
    return call("getValue", {
        app: APP_NAME,
        key: dataName,
        token: token
    });
}

// Don't touch

function call(action = null, parameters = null, callback = null) {
    // Create the query
    let query = "";
    for (let key of parameters) {
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
    let result = await(await fetch(url)).text();
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