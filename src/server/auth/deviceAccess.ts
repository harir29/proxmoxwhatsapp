import type { IncomingMessage, ServerResponse } from 'http';
import type WS from 'ws';
import { Config } from '../Config';
import { resolveUserId } from './currentUser';

export function canAccessDevice(userId: number, udid: string): boolean {
    return Config.getInstance().db.deviceAccess.canAccess(userId, udid);
}

export function requireDeviceAccess(req: IncomingMessage, res: ServerResponse, udid: string): boolean {
    if (canAccessDevice(resolveUserId(req), udid)) return true;
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'device access denied' }));
    return false;
}

export function requireWsDeviceAccess(ws: WS, userId: number, udid: string): boolean {
    if (canAccessDevice(userId, udid)) return true;
    ws.close(4403, 'device access denied');
    return false;
}
