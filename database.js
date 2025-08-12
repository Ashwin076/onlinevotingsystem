const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root2',
    password: process.env.DB_PASSWORD || '12345',
    database: process.env.DB_NAME || 'online_voting_system',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

module.exports = {
    query: async (sql, params) => {
        const [rows] = await pool.execute(sql, params);
        return rows;
    },
    getConnection: async () => {
        return await pool.getConnection();
    }
};