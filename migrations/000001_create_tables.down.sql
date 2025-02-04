-- migrations/000001_create_tables.down.sql
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_user_credentials_updated_at ON user_credentials;
DROP FUNCTION IF EXISTS update_updated_at_column();
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS user_credentials;
DROP EXTENSION IF EXISTS "uuid-ossp";