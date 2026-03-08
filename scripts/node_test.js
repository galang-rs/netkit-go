// scripts/node_test.js
const axios = require('axios');
const jwt = require("jsonwebtoken");
const { of } = require("rxjs");
const { map } = require("rxjs/operators");

module.exports = {
    message: "Hello from Node.js process!",
    greet: (name) => `Hello ${name} from Node.js!`,
    shuffle: (arr) => {
        return arr.sort(() => Math.random() - 0.5);
    },
    add: (a, b) => {
        console.log(`[Node] Adding ${a} + ${b}`);
        return a + b;
    },
    getData: () => {
        return { status: "ok", timestamp: Date.now() };
    },
    fetchTest: async () => {
        const response = await axios.get('https://jsonplaceholder.typicode.com/posts/1');
        return response.data;
    },
    generateToken: () => {
        const token = jwt.sign({ user: "admin" }, "secret", { expiresIn: "1h" });
        return token;
    },
    verifyToken: (token) => {
        const decoded = jwt.verify(token, "secret");
        return decoded;
    },
    rxTest: () => {
        return of(1, 2, 3, 4)
            .pipe(
                map(x => x * 10)
            )
            .toPromise();
    }
};
