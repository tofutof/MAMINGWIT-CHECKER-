-- ============================================================
-- MAMINGWIT CHECKER - Database Schema
-- Phishing & Malicious URL Detection System
-- ============================================================

CREATE DATABASE IF NOT EXISTS mamingwit_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE mamingwit_db;

-- URL Checks History Table
CREATE TABLE IF NOT EXISTS url_checks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url TEXT NOT NULL,
    url_hash VARCHAR(64) NOT NULL,
    domain VARCHAR(255),
    protocol VARCHAR(10),
    risk_score INT DEFAULT 0,
    risk_level ENUM('low','medium','high') DEFAULT 'low',
    flags_triggered JSON,
    is_https TINYINT(1) DEFAULT 0,
    url_length INT DEFAULT 0,
    param_count INT DEFAULT 0,
    uses_ip TINYINT(1) DEFAULT 0,
    has_phishing_keywords TINYINT(1) DEFAULT 0,
    suspicious_domain TINYINT(1) DEFAULT 0,
    check_count INT DEFAULT 1,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_checked DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    INDEX idx_url_hash (url_hash),
    INDEX idx_risk_level (risk_level),
    INDEX idx_last_checked (last_checked)
) ENGINE=InnoDB;

-- Community Reports Table
CREATE TABLE IF NOT EXISTS community_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url_hash VARCHAR(64) NOT NULL,
    url TEXT NOT NULL,
    reporter_ip VARCHAR(45),
    report_reason VARCHAR(255),
    reported_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_url_hash (url_hash)
) ENGINE=InnoDB;

-- Known Phishing Domains Blacklist
CREATE TABLE IF NOT EXISTS blacklist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    reason VARCHAR(500),
    severity ENUM('medium','high','critical') DEFAULT 'high',
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_domain (domain)
) ENGINE=InnoDB;

-- Phishing Keywords Table
CREATE TABLE IF NOT EXISTS phishing_keywords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    keyword VARCHAR(100) NOT NULL UNIQUE,
    weight INT DEFAULT 10,
    category VARCHAR(50)
) ENGINE=InnoDB;

-- ============================================================
-- Seed Data: Known Phishing Domains
-- ============================================================
INSERT IGNORE INTO blacklist (domain, reason, severity) VALUES
('paypa1.com', 'PayPal phishing clone', 'critical'),
('arnazon.com', 'Amazon phishing clone', 'critical'),
('g00gle.com', 'Google phishing clone', 'critical'),
('microsooft.com', 'Microsoft phishing clone', 'critical'),
('faceb00k.com', 'Facebook phishing clone', 'critical'),
('netfl1x.com', 'Netflix phishing clone', 'high'),
('appleid-verify.com', 'Apple ID phishing', 'critical'),
('secure-bankofamerica.com', 'Bank of America phishing', 'critical'),
('login-paypal-secure.com', 'PayPal phishing', 'critical'),
('verify-account-google.net', 'Google account phishing', 'critical');

-- ============================================================
-- Seed Data: Phishing Keywords
-- ============================================================
INSERT IGNORE INTO phishing_keywords (keyword, weight, category) VALUES
('login', 8, 'auth'),
('verify', 10, 'auth'),
('update', 7, 'auth'),
('secure', 6, 'security'),
('account', 5, 'auth'),
('banking', 9, 'finance'),
('password', 10, 'auth'),
('confirm', 8, 'auth'),
('free', 5, 'lure'),
('winner', 7, 'lure'),
('prize', 7, 'lure'),
('urgent', 8, 'pressure'),
('suspended', 9, 'pressure'),
('expire', 8, 'pressure'),
('click', 4, 'action'),
('claim', 6, 'lure'),
('paypal', 8, 'brand'),
('amazon', 6, 'brand'),
('netflix', 6, 'brand'),
('apple', 5, 'brand'),
('google', 5, 'brand'),
('microsoft', 5, 'brand'),
('webscr', 10, 'tech'),
('signin', 8, 'auth'),
('credential', 9, 'auth');