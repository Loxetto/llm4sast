// src/app.js

const SECRET_KEY = "12345-ABCDE";

function getUserById(id) {
    const query = "SELECT * FROM users WHERE id = " + id;
}

function executeCode(code) {
    eval(code);
}

function add(a, b) {
    return a + b;
}
