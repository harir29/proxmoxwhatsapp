import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import { SettingsApi } from '../api/SettingsApi';
import { Config } from '../Config';
import { IMPLICIT_ADMIN_ID } from '../db/constants';
import { EnvName } from '../EnvName';
import { makeReqRes } from './helpers/httpMock';

const tmpDirs: string[] = [];
const saved = { CONFIG: process.env[EnvName.CONFIG_PATH], DEPS: process.env['DEPS_PATH'] };
function setup(): void {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wsset-'));
    tmpDirs.push(dir);
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ webPort: 8000 }));
    process.env[EnvName.CONFIG_PATH] = path.join(dir, 'config.json');
    process.env['DEPS_PATH'] = path.join(dir, 'deps');
    Config._resetForTest();
}
afterEach(() => {
    Config._resetForTest();
    if (saved.CONFIG === undefined) delete process.env[EnvName.CONFIG_PATH];
    else process.env[EnvName.CONFIG_PATH] = saved.CONFIG;
    if (saved.DEPS === undefined) delete process.env['DEPS_PATH'];
    else process.env['DEPS_PATH'] = saved.DEPS;
    while (tmpDirs.length) fs.rmSync(tmpDirs.pop()!, { recursive: true, force: true });
});

describe('SettingsApi', () => {
    it('PATCH then GET global settings for the implicit admin', async () => {
        setup();
        const cfg = Config.getInstance();
        const api = new SettingsApi();
        const patch = makeReqRes('PATCH', '/api/settings', { theme: 'dark', scanSubnets: ['10.0.0.0/24'] });
        await api.handle(patch.req, patch.res);
        expect(cfg.db.userSettings.get(IMPLICIT_ADMIN_ID, 'theme')).toBe('dark');
        const get = makeReqRes('GET', '/api/settings');
        await api.handle(get.req, get.res);
        expect(get.getJson()).toMatchObject({ theme: 'dark', scanSubnets: ['10.0.0.0/24'] });
    });

    it('PATCH per-device settings then GET by udid', async () => {
        setup();
        const cfg = Config.getInstance();
        const api = new SettingsApi();
        const patch = makeReqRes('PATCH', '/api/settings/device?udid=UDID1', { audio: { source: 'output' } });
        await api.handle(patch.req, patch.res);
        expect(cfg.db.devices.getDeviceSetting(IMPLICIT_ADMIN_ID, 'UDID1', 'audio')).toEqual({ source: 'output' });
        const get = makeReqRes('GET', '/api/settings/device?udid=UDID1');
        await api.handle(get.req, get.res);
        expect(get.getJson()).toEqual({ audio: { source: 'output' } });
    });

    it('reset clears user_settings + labels + device_settings for the caller', async () => {
        setup();
        const db = Config.getInstance().db;
        db.userSettings.set(IMPLICIT_ADMIN_ID, 'theme', 'dark');
        db.devices.setLabel(IMPLICIT_ADMIN_ID, 'S1', 'TV');
        db.devices.setDeviceSetting(IMPLICIT_ADMIN_ID, 'UDID1', 'audio', { source: 'mic' });
        const api = new SettingsApi();
        const r = makeReqRes('POST', '/api/settings/reset', {});
        await api.handle(r.req, r.res);
        expect(db.userSettings.getAll(IMPLICIT_ADMIN_ID)).toEqual({});
        expect(db.devices.getAllLabels(IMPLICIT_ADMIN_ID)).toEqual({});
        expect(db.devices.getDeviceSettings(IMPLICIT_ADMIN_ID, 'UDID1')).toEqual({});
    });

    it('denies per-device settings for a device not assigned to the user', async () => {
        setup();
        const db = Config.getInstance().db;
        const user = db.users.create({ username: 'user1', role: 'user', passwordHash: null });
        db.deviceAccess.assign(user.id, '127.0.0.1:5555', true);
        const api = new SettingsApi();

        const denied = makeReqRes('GET', '/api/settings/device?udid=127.0.0.1%3A5556');
        (denied.req as typeof denied.req & { user: { id: number } }).user = { id: user.id };
        await api.handle(denied.req, denied.res);
        expect(denied.getStatus()).toBe(403);

        const allowed = makeReqRes('GET', '/api/settings/device?udid=127.0.0.1%3A5555');
        (allowed.req as typeof allowed.req & { user: { id: number } }).user = { id: user.id };
        await api.handle(allowed.req, allowed.res);
        expect(allowed.getStatus()).toBe(200);
    });
});
