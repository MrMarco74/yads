-- Database backup — testlab exposure target
-- This file should be detected by content_discovery / git_exposure scanner

CREATE DATABASE IF NOT EXISTS webapp_prod;
USE webapp_prod;

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50),
    password_hash VARCHAR(255),
    email VARCHAR(100),
    role ENUM('admin','user') DEFAULT 'user'
);

INSERT INTO users VALUES (1, 'admin', '$2b$12$fakehashadmin', 'admin@testlab.local', 'admin');
INSERT INTO users VALUES (2, 'testuser', '$2b$12$fakehashuser', 'user@testlab.local', 'user');
