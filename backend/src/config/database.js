const { Pool } = require("pg");
const logger = require("./logger");

const dbConfig = {
  host:     process.env.DB_HOST     || "localhost",
  port:     parseInt(process.env.DB_PORT || "5432"),
  user:     process.env.DB_USER     || "postgres",
  password: process.env.DB_PASSWORD || "postgres",
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
};

const pool = new Pool({ ...dbConfig, database: process.env.DB_NAME || "taskmanager" });

pool.on("error", (err) => {
  logger.error("Unexpected error on idle client", { error: err.message });
});

const connectDB = async () => {
  try {
    const adminPool = new Pool({ ...dbConfig, database: "postgres" });
    const adminClient = await adminPool.connect();
    const dbName = process.env.DB_NAME || "taskmanager";
    try {
      const res = await adminClient.query(`SELECT datname FROM pg_catalog.pg_database WHERE datname = $1`, [dbName]);
      if (res.rowCount === 0) {
        logger.info(`Database ${dbName} does not exist. Creating...`);
        await adminClient.query(`CREATE DATABASE ${dbName}`);
        logger.info(`Database ${dbName} created successfully.`);
      }
    } finally {
      adminClient.release();
      await adminPool.end();
    }

    const client = await pool.connect();
    
    logger.info("Verifying and applying database schema...");
    const schemaSql = `
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name          VARCHAR(100)  NOT NULL,
    email         VARCHAR(255)  NOT NULL UNIQUE,
    password_hash TEXT          NOT NULL,
    created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS tasks (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title       VARCHAR(255)  NOT NULL,
    description TEXT,
    status      VARCHAR(20)   NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'completed')),
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tasks_user_id     ON tasks(user_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status      ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_user_status ON tasks(user_id, status);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_tasks_updated_at ON tasks;
CREATE TRIGGER set_tasks_updated_at
    BEFORE UPDATE ON tasks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
    `;
    await client.query(schemaSql);
    logger.info("PostgreSQL connected and schema applied successfully");
    client.release();
  } catch (err) {
    logger.error("Failed to connect to PostgreSQL or apply schema", { error: err.stack || err.message });
    process.exit(1);
  }
};

module.exports = { pool, connectDB };
