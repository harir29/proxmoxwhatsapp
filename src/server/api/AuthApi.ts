import type { IncomingMessage, ServerResponse } from 'http';
import {
    isAccessControlEnabled,
    parseCookie,
    SESSION_COOKIE,
    sessionCookie,
    setAuthEnabled,
} from '../auth/authState';
import { OidcService } from '../auth/OidcService';
import { isOidcEnabled } from '../auth/oidcConfig';
import { resolveUserId } from '../auth/currentUser';
import { login } from '../auth/loginService';
import { hashPassword, verifyPassword } from '../auth/password';
import { requireAdmin } from '../auth/requireAdmin';
import { SessionStore } from '../auth/session';
import { Config } from '../Config';
import { IMPLICIT_ADMIN_ID } from '../db/constants';
import { Logger } from '../Logger';
import { readJsonBody } from './utils';

const log = Logger.for('AuthApi');

function sendJson(res: ServerResponse, status: number, body: unknown): void {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
}

export class AuthApi {
    async handle(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
        const pathname = new URL(req.url ?? '/', 'http://localhost').pathname;
        if (!pathname.startsWith('/api/auth/')) return false;

        const db = Config.getInstance().db;

        if (req.method === 'GET' && pathname === '/api/auth/oidc/login') {
            if (!isOidcEnabled(db)) {
                sendJson(res, 404, { error: 'OIDC is not enabled' });
                return true;
            }
            const url = new URL(req.url ?? '/', 'http://localhost');
            try {
                const location = await OidcService.getInstance().authorizationUrl(db, url.searchParams.get('returnTo'));
                res.writeHead(302, { location, 'cache-control': 'no-store' });
                res.end();
            } catch {
                sendJson(res, 503, { error: 'identity provider unavailable' });
            }
            return true;
        }

        if (req.method === 'GET' && pathname === '/api/auth/oidc/callback') {
            const url = new URL(req.url ?? '/', 'http://localhost');
            const code = url.searchParams.get('code') || '';
            const state = url.searchParams.get('state') || '';
            if (!code || !state || url.searchParams.has('error')) {
                sendJson(res, 400, { error: 'OIDC login was not completed' });
                return true;
            }
            try {
                const result = await OidcService.getInstance().completeCallback(db, code, state);
                const token = new SessionStore(db.sqlite).create(result.user.id, Date.now());
                const forwardedProto = req.headers['x-forwarded-proto'];
                const secure =
                    Boolean((req.socket as { encrypted?: boolean } | undefined)?.encrypted) ||
                    (typeof forwardedProto === 'string' && forwardedProto.split(',')[0]?.trim() === 'https');
                res.setHeader('Set-Cookie', sessionCookie(token, secure));
                res.writeHead(302, { location: result.returnTo, 'cache-control': 'no-store' });
                res.end();
            } catch (error) {
                const message = error instanceof Error ? error.message : String(error);
                log.warn(`OIDC callback failed: ${message}`);
                sendJson(res, 403, { error: 'OIDC login failed or account is not authorized' });
            }
            return true;
        }

        if (req.method === 'GET' && pathname === '/api/auth/oidc/logout') {
            const token = parseCookie(req.headers.cookie)[SESSION_COOKIE];
            if (token) new SessionStore(db.sqlite).delete(token);
            res.setHeader('Set-Cookie', sessionCookie('', true, 0));
            try {
                const location = await OidcService.getInstance().logoutUrl(db);
                res.writeHead(302, { location, 'cache-control': 'no-store' });
                res.end();
            } catch {
                res.writeHead(302, { location: '/' });
                res.end();
            }
            return true;
        }

        if (req.method === 'POST' && pathname === '/api/auth/login') {
            const body = await readJsonBody(req);
            const username = typeof body['username'] === 'string' ? body['username'] : '';
            const password = typeof body['password'] === 'string' ? body['password'] : '';
            const result = login(db, username, password, Date.now());
            if (result.ok) {
                const forwardedProto = req.headers['x-forwarded-proto'];
                const secure =
                    Boolean((req.socket as { encrypted?: boolean } | undefined)?.encrypted) ||
                    (typeof forwardedProto === 'string' && forwardedProto.split(',')[0]?.trim() === 'https');
                res.setHeader(
                    'Set-Cookie',
                    sessionCookie(result.token, secure),
                );
                sendJson(res, 200, { ok: true });
            } else {
                sendJson(res, 401, { ok: false, reason: result.reason });
            }
            return true;
        }

        if (req.method === 'POST' && pathname === '/api/auth/logout') {
            const token = parseCookie(req.headers.cookie)[SESSION_COOKIE];
            if (token) new SessionStore(db.sqlite).delete(token);
            const forwardedProto = req.headers['x-forwarded-proto'];
            const secure =
                Boolean((req.socket as { encrypted?: boolean } | undefined)?.encrypted) ||
                (typeof forwardedProto === 'string' && forwardedProto.split(',')[0]?.trim() === 'https');
            res.setHeader('Set-Cookie', sessionCookie('', secure, 0));
            sendJson(res, 200, { ok: true });
            return true;
        }

        if (req.method === 'GET' && pathname === '/api/auth/me') {
            // ALLOW-LISTED route → self-validate the cookie (AuthGate did not attach req.user here).
            if (!isAccessControlEnabled(db)) {
                const admin = db.users.getById(IMPLICIT_ADMIN_ID);
                sendJson(res, 200, {
                    authEnabled: false,
                    oidcEnabled: false,
                    user: admin ? { username: admin.username, role: admin.role } : null,
                });
                return true;
            }
            const token = parseCookie(req.headers.cookie)[SESSION_COOKIE];
            const session = token ? new SessionStore(db.sqlite).findValid(token, Date.now()) : undefined;
            const user = session ? db.users.getById(session.userId) : undefined;
            const assignments = user ? db.deviceAccess.listForUser(user.id) : [];
            sendJson(res, 200, {
                authEnabled: true,
                oidcEnabled: isOidcEnabled(db),
                user: user ? { id: user.id, username: user.username, role: user.role } : null,
                devices: user?.role === 'admin' ? [] : assignments.map((assignment) => assignment.udid),
                defaultDevice:
                    !user || user.role === 'admin' ? null : db.deviceAccess.defaultForUser(user.id) || null,
            });
            return true;
        }

        if (req.method === 'POST' && pathname === '/api/auth/change-password') {
            const body = await readJsonBody(req);
            const current = typeof body['currentPassword'] === 'string' ? body['currentPassword'] : '';
            const next = typeof body['newPassword'] === 'string' ? body['newPassword'] : '';
            if (next.length === 0) {
                sendJson(res, 400, { error: 'newPassword required' });
                return true;
            }
            const user = db.users.getById(resolveUserId(req));
            if (!user?.passwordHash || !verifyPassword(current, user.passwordHash)) {
                sendJson(res, 400, { error: 'current password incorrect' });
                return true;
            }
            db.users.setPasswordHash(user.id, hashPassword(next));
            sendJson(res, 200, { ok: true });
            return true;
        }

        if (req.method === 'POST' && pathname === '/api/auth/enable') {
            if (!requireAdmin(req, res)) return true;
            if (db.users.countEnabledAdminsWithPassword() < 1) {
                sendJson(res, 409, { error: 'set an admin password before enabling auth' });
                return true;
            }
            setAuthEnabled(db, true);
            sendJson(res, 200, { ok: true });
            return true;
        }

        if (req.method === 'POST' && pathname === '/api/auth/disable') {
            if (!requireAdmin(req, res)) return true;
            setAuthEnabled(db, false);
            sendJson(res, 200, { ok: true });
            return true;
        }

        return false;
    }
}
