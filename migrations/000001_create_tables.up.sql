-- migrations/000001_create_tables.up.sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create user_credentials table
CREATE TABLE user_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash BYTEA NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    verification_token UUID,
    verification_token_expires_at TIMESTAMP WITH TIME ZONE,
    reset_token UUID,
    reset_token_expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    credential_id UUID NOT NULL REFERENCES user_credentials(id) ON DELETE CASCADE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    student_number VARCHAR(50) UNIQUE NOT NULL,
    accepted_privacy_policy BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create trigger function for updating timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers
CREATE TRIGGER update_user_credentials_updated_at
    BEFORE UPDATE ON user_credentials
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create indexes
CREATE INDEX idx_user_credentials_email ON user_credentials(email);
CREATE INDEX idx_users_student_number ON users(student_number);
CREATE INDEX idx_user_credentials_verification ON user_credentials(verification_token) WHERE verification_token IS NOT NULL;
CREATE INDEX idx_user_credentials_reset ON user_credentials(reset_token) WHERE reset_token IS NOT NULL;

