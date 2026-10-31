ALTER TABLE users
    DROP CONSTRAINT chk_users_status;

UPDATE users SET status = 'DEACTIVATED' WHERE status = 'INACTIVE';

ALTER TABLE users
    ADD CONSTRAINT chk_users_status
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DEACTIVATED'));
