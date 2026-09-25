import type { DatabaseSync } from 'node:sqlite';
import type { Migration } from '../migrations';

export const migration002: Migration = {
    version: 2,
    up(db: DatabaseSync): void {
        db.exec(`
ALTER TABLE users ADD COLUMN oidc_issuer TEXT;
ALTER TABLE users ADD COLUMN oidc_subject TEXT;
CREATE UNIQUE INDEX idx_users_oidc_identity
    ON users(oidc_issuer, oidc_subject)
    WHERE oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL;

CREATE TABLE device_assignments (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    udid       TEXT    NOT NULL,
    is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, udid)
);
CREATE UNIQUE INDEX idx_device_assignments_one_default
    ON device_assignments(user_id)
    WHERE is_default = 1;
CREATE INDEX idx_device_assignments_udid ON device_assignments(udid);
        `);
    },
};
