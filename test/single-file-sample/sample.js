const userInput = process.env.USER_INPUT || '';
const query = "SELECT * FROM users WHERE name = '" + userInput + "'";
console.log(query);
