require("dotenv").config();
const { Pool } = require("pg");
console.log("Connecting to database:", process.env.DATABASE_URL);
const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

const connectDB = async () => {
    try {
        await pool.connect();
        console.log("Connected to PostgreSQL");
    } catch (error) {
        console.error("Database connection error: ", error);
        process.exit(1);
    }
};

module.exports = {  pool, connectDB };
