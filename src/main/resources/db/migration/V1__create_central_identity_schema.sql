
CREATE TABLE users (
                       user_id UUID PRIMARY KEY,
                       email VARCHAR(254) NOT NULL UNIQUE,
                       password_hash TEXT NOT NULL,
                       full_name VARCHAR(150) NOT NULL,
                       status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
                       failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                       locked_until TIMESTAMPTZ,
                       last_login_at TIMESTAMPTZ,
                       created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                       updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

                       CONSTRAINT chk_users_status
                           CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DEACTIVATED')),

                       CONSTRAINT chk_users_failed_login_attempts
                           CHECK (failed_login_attempts >= 0)
);

CREATE TABLE user_profiles (
                               user_id UUID PRIMARY KEY,
                               avatar_url TEXT,
                               bio TEXT,
                               phone_number VARCHAR(30),
                               date_of_birth DATE,
                               locale VARCHAR(20),
                               timezone VARCHAR(64),
                               updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

                               CONSTRAINT fk_user_profiles_user
                                   FOREIGN KEY (user_id)
                                       REFERENCES users(user_id)
                                       ON DELETE CASCADE
);

CREATE TABLE password_resets (
                                 reset_id UUID PRIMARY KEY,
                                 user_id UUID NOT NULL,
                                 token_hash TEXT NOT NULL UNIQUE,
                                 expires_at TIMESTAMPTZ NOT NULL,
                                 is_used BOOLEAN NOT NULL DEFAULT FALSE,
                                 ip_requested INET,
                                 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

                                 CONSTRAINT chk_password_resets_expiry
                                     CHECK (expires_at > created_at),

                                 CONSTRAINT fk_password_resets_user
                                     FOREIGN KEY (user_id)
                                         REFERENCES users(user_id)
);

CREATE TABLE lms_clients (
                             client_id VARCHAR(100) PRIMARY KEY,
                             client_secret_hash TEXT,
                             client_name VARCHAR(200) NOT NULL,
                             redirect_uris TEXT[] NOT NULL,
                             is_active BOOLEAN NOT NULL DEFAULT TRUE,
                             created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
