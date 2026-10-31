ALTER TABLE users
    DROP CONSTRAINT chk_users_status;

ALTER TABLE users
    ADD CONSTRAINT chk_users_status
        CHECK (status IN ('ACTIVE', 'INACTIVE', 'SUSPENDED', 'DEACTIVATED'));
