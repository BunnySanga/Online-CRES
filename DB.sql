-- 1. core tables
CREATE TABLE Admin (
  admin_id VARCHAR(20) PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(100) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE Class (
  class_id INT AUTO_INCREMENT PRIMARY KEY,
  class_name VARCHAR(100) NOT NULL
);

CREATE TABLE Student (
  student_id VARCHAR(20) PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  date_of_birth DATE NOT NULL,
  class_id INT,
  password_hash VARCHAR(255) NOT NULL,
  must_change_password BOOLEAN DEFAULT TRUE,
  last_login DATETIME,
  email VARCHAR(100),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (class_id) REFERENCES Class(class_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE Election (
  election_id INT AUTO_INCREMENT PRIMARY KEY,
  class_id INT NOT NULL,
  nomination_start DATETIME NOT NULL,
  nomination_end DATETIME NOT NULL,
  voting_start DATETIME NOT NULL,
  voting_end DATETIME NOT NULL,
  is_active BOOLEAN DEFAULT FALSE,
  is_published BOOLEAN DEFAULT FALSE,
  created_by_admin_id VARCHAR(20),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (class_id) REFERENCES Class(class_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (created_by_admin_id) REFERENCES Admin(admin_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE Nomination (
  nomination_id INT AUTO_INCREMENT PRIMARY KEY,
  election_id INT NOT NULL,
  student_id VARCHAR(20) NOT NULL,
  manifesto TEXT,
  photo_url VARCHAR(255),
  status ENUM('PENDING','APPROVED','REJECTED') DEFAULT 'PENDING',
  submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  reviewed_by_admin_id VARCHAR(20),
  reviewed_at DATETIME,
  rejection_reason TEXT,
  FOREIGN KEY (election_id) REFERENCES Election(election_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (student_id) REFERENCES Student(student_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (reviewed_by_admin_id) REFERENCES Admin(admin_id) ON DELETE CASCADE ON UPDATE CASCADE,
  UNIQUE KEY ux_nomination (election_id, student_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE OTP (
  otp_id INT AUTO_INCREMENT PRIMARY KEY,
  student_id VARCHAR(20) NOT NULL,
  otp_code VARCHAR(10) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expiry_time DATETIME NOT NULL,
  purpose ENUM('LOGIN','RESET') DEFAULT 'LOGIN',
  used BOOLEAN DEFAULT FALSE,
  FOREIGN KEY (student_id) REFERENCES Student(student_id) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Separate OTP table for Admin accounts (mirrors OTP but references Admin)
CREATE TABLE IF NOT EXISTS AdminOTP (
  otp_id INT AUTO_INCREMENT PRIMARY KEY,
  admin_id VARCHAR(20) NOT NULL,
  otp_code VARCHAR(10) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expiry_time DATETIME NOT NULL,
  purpose ENUM('RESET') DEFAULT 'RESET',
  used BOOLEAN DEFAULT FALSE,
  FOREIGN KEY (admin_id) REFERENCES Admin(admin_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE Policy (
  policy_id INT AUTO_INCREMENT PRIMARY KEY,
  policy_text TEXT NOT NULL,
  version INT DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  created_by_admin_id VARCHAR(20),
  FOREIGN KEY (created_by_admin_id) REFERENCES Admin(admin_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE PolicyAcceptance (
  acceptance_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(20) NOT NULL,
  policy_id INT NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  user_role ENUM('ADMIN','STUDENT') DEFAULT 'STUDENT',
  FOREIGN KEY (policy_id) REFERENCES Policy(policy_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE Session (
  session_id VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(20) NOT NULL,
  role ENUM('ADMIN','STUDENT') NOT NULL,
  creation_time DATETIME DEFAULT CURRENT_TIMESTAMP,
  expiry_time DATETIME NOT NULL
);

CREATE TABLE AuditLog (
  log_id INT AUTO_INCREMENT PRIMARY KEY,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  user_id VARCHAR(20),
  role ENUM('ADMIN','STUDENT','SYSTEM') DEFAULT 'SYSTEM',
  ip_address VARCHAR(45),
  action_type VARCHAR(80),
  details JSON,
  outcome ENUM('SUCCESS','FAILURE') DEFAULT 'SUCCESS'
);

-- 2. voting-specific tables for anonymity & per-election voter tracking
CREATE TABLE VotingToken (
  token_id VARCHAR(64) PRIMARY KEY,
  student_id VARCHAR(20),
  election_id INT NOT NULL,
  token_hash VARCHAR(255),
  issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  used BOOLEAN DEFAULT FALSE,
  used_at DATETIME,
  FOREIGN KEY (student_id) REFERENCES Student(student_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (election_id) REFERENCES Election(election_id) ON DELETE CASCADE ON UPDATE CASCADE,
  INDEX ix_vt_election_used (election_id, used),
  INDEX ix_vt_token_hash (token_hash)
);

CREATE TABLE VoterStatus (
  id INT AUTO_INCREMENT PRIMARY KEY,
  student_id VARCHAR(20) NOT NULL,
  election_id INT NOT NULL,
  has_voted BOOLEAN DEFAULT FALSE,
  voted_at DATETIME,
  UNIQUE KEY ux_voter_status (student_id, election_id),
  FOREIGN KEY (student_id) REFERENCES Student(student_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (election_id) REFERENCES Election(election_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE VoteAnonymous (
  vote_id INT AUTO_INCREMENT PRIMARY KEY,
  election_id INT NOT NULL,
  ballot_id VARCHAR(64) NOT NULL,
  candidate_id VARCHAR(20) NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (election_id) REFERENCES Election(election_id) ON DELETE CASCADE ON UPDATE CASCADE,
  INDEX ix_vote_election (election_id)
);
