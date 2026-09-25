import { DatabaseSync } from 'node:sqlite';
import { beforeEach, describe, expect, it } from 'vitest';
import { DeviceAccessStore } from '../DeviceAccessStore';
import { runMigrations } from '../migrations';
import { UserStore } from '../UserStore';

describe('DeviceAccessStore', () => {
    let db: DatabaseSync;
    let users: UserStore;
    let access: DeviceAccessStore;

    beforeEach(() => {
        db = new DatabaseSync(':memory:');
        db.exec('PRAGMA foreign_keys = ON');
        runMigrations(db);
        users = new UserStore(db);
        access = new DeviceAccessStore(db);
    });

    it('allows admins to access every device', () => {
        expect(access.canAccess(1, '127.0.0.1:5558')).toBe(true);
    });

    it('allows a user only their assigned device', () => {
        const user = users.create({ username: 'user1', role: 'user', passwordHash: null });
        access.assign(user.id, '127.0.0.1:5555', true);
        expect(access.canAccess(user.id, '127.0.0.1:5555')).toBe(true);
        expect(access.canAccess(user.id, '127.0.0.1:5556')).toBe(false);
        expect(access.defaultForUser(user.id)).toBe('127.0.0.1:5555');
    });

    it('keeps only one default device per user', () => {
        const user = users.create({ username: 'user2', role: 'user', passwordHash: null });
        access.assign(user.id, '127.0.0.1:5556', true);
        access.assign(user.id, '127.0.0.1:5557', true);
        expect(access.listForUser(user.id)).toEqual([
            expect.objectContaining({ udid: '127.0.0.1:5557', isDefault: true }),
            expect.objectContaining({ udid: '127.0.0.1:5556', isDefault: false }),
        ]);
    });
});
