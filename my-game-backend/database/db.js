const mysql = require("mysql");
const dotenv = require("dotenv");
const util = require('util');
dotenv.config();

const pool = mysql.createPool({
  host: process.env.host,
  user: process.env.user,
  database: process.env.database,
  port: process.env.DB_PORT || 3306,
  timezone: '+05:30'
});


// connection.connect((error) => {
//   if (error) {
//     throw error;
//     console.log("Database connection failed: " + error.message);
//   } else {
//     console.log("Database connected successfully");
//   }
// });

pool.query = util.promisify(pool.query);

// કનેક્શન ચેક કરવા માટે (વૈકલ્પિક પણ ભલામણ કરેલ)
pool.getConnection((err, connection) => {
  if (err) {
    console.error(" Database connection error:", err);
    return;
  }
  console.log("connected to the database successfully");
  connection.release(); // કનેક્શનને પાછું પૂલમાં મોકલો
});

pool.query = util.promisify(pool.query);

module.exports = pool;