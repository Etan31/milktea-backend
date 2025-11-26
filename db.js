// db.js
import pkg from 'pg';
import dotenv from 'dotenv';
dotenv.config();

const { Pool } = pkg;

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'milktea_db',
  password: process.env.DB_PASSWORD || '',
  port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
});

pool.on('connect', () => console.log('✅ PostgreSQL Connected'));

export default pool;
