import type { DatabaseSync } from 'node:sqlite';

export interface DeviceAssignment {
    userId: number;
    udid: string;
    isDefault: boolean;
    createdAt: number;
}

type AssignmentRow = {
    user_id: number;
    udid: string;
    is_default: number;
    created_at: number;
};

function toAssignment(row: AssignmentRow): DeviceAssignment {
    return {
        userId: row.user_id,
        udid: row.udid,
        isDefault: row.is_default === 1,
        createdAt: row.created_at,
    };
}

export class DeviceAccessStore {
    constructor(private readonly db: DatabaseSync) {}

    canAccess(userId: number, udid: string): boolean {
        const user = this.db.prepare('SELECT role, disabled FROM users WHERE id = ?').get(userId) as
            | { role: string; disabled: number }
            | undefined;
        if (!user || user.disabled === 1) return false;
        if (user.role === 'admin') return true;
        return Boolean(
            this.db
                .prepare('SELECT 1 FROM device_assignments WHERE user_id = ? AND udid = ?')
                .get(userId, udid),
        );
    }

    listForUser(userId: number): DeviceAssignment[] {
        return (
            this.db
                .prepare(
                    'SELECT user_id, udid, is_default, created_at FROM device_assignments WHERE user_id = ? ORDER BY is_default DESC, udid',
                )
                .all(userId) as AssignmentRow[]
        ).map(toAssignment);
    }

    listAll(): DeviceAssignment[] {
        return (
            this.db
                .prepare(
                    'SELECT user_id, udid, is_default, created_at FROM device_assignments ORDER BY user_id, is_default DESC, udid',
                )
                .all() as AssignmentRow[]
        ).map(toAssignment);
    }

    defaultForUser(userId: number): string | undefined {
        const row = this.db
            .prepare('SELECT udid FROM device_assignments WHERE user_id = ? ORDER BY is_default DESC, udid LIMIT 1')
            .get(userId) as { udid: string } | undefined;
        return row?.udid;
    }

    assign(userId: number, udid: string, isDefault = false): void {
        this.db.exec('BEGIN');
        try {
            if (isDefault) {
                this.db.prepare('UPDATE device_assignments SET is_default = 0 WHERE user_id = ?').run(userId);
            }
            this.db
                .prepare(
                    `INSERT INTO device_assignments (user_id, udid, is_default, created_at)
                     VALUES (?, ?, ?, ?)
                     ON CONFLICT(user_id, udid) DO UPDATE SET is_default = excluded.is_default`,
                )
                .run(userId, udid, isDefault ? 1 : 0, Date.now());
            this.db.exec('COMMIT');
        } catch (error) {
            this.db.exec('ROLLBACK');
            throw error;
        }
    }

    revoke(userId: number, udid: string): void {
        this.db.prepare('DELETE FROM device_assignments WHERE user_id = ? AND udid = ?').run(userId, udid);
    }
}
