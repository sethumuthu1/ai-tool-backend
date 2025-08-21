const mysql = require("mysql2/promise");

const db = mysql.createPool({
  host: "localhost",       // ✅ Your DB host
  user: "root",            // ✅ Your DB user
  password: "root",            // ✅ Your DB password
  database: "ai_system", // ✅ Your actual database name
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = db;
