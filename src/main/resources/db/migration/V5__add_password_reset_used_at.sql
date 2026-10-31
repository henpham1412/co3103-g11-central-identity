-- Preserve legacy is_used flags; their actual consumption times are unknown.
ALTER TABLE password_resets ADD COLUMN used_at TIMESTAMPTZ;
