
-- Secure Login System
-- AI Security Alerts Database Setup

CREATE DATABASE IF NOT EXISTS secure_login_db;

USE secure_login_db;

-- Store AI security alerts
CREATE TABLE IF NOT EXISTS security_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT NOT NULL,
    ip_address VARCHAR(45) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_alert_type (alert_type),
    INDEX idx_created_at (created_at)
);

-- Add admin permissions to existing users table
-- Run only if is_admin does not already exist.
-- ALTER TABLE users
-- ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE;
