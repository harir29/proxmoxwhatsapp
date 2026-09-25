import { AUTH_ENABLED_KEY } from '../db/constants';
import type { Db } from '../db/Db';
import { isOidcEnabled } from './oidcConfig';

export const SESSION_COOKIE = 'wsscrcpy_sid';

// `/login` is NOT here: AuthGate serves the login page body itself (see Task 8) so it never
// falls through to the SPA catch-all (`createStaticHandler` serves index.html for any non-file
// path — Auditor finding: app-shell leak). whoami + me are exempt from the AUTH gate only;
// /api/whoami is still gated upstream by the per-instance token check (requestGate #367), so
// allow-listing it here does not make it reachable cross-instance without the instance token.
const ALLOWLIST_EXACT = new Set([
    '/api/auth/login',
    '/api/auth/me',
    '/api/auth/oidc/login',
    '/api/auth/oidc/callback',
    '/api/auth/oidc/logout',
    '/api/whoami',
]);
const ALLOWLIST_PREFIX = ['/login-assets/']; // the login page's own self-contained assets

export function isAuthEnabled(db: Db): boolean {
    return db.appSettings.get(AUTH_ENABLED_KEY) === true;
}
export function isAccessControlEnabled(db: Db): boolean {
    return isAuthEnabled(db) || isOidcEnabled(db);
}
export function setAuthEnabled(db: Db, on: boolean): void {
    db.appSettings.set(AUTH_ENABLED_KEY, on);
}

export function parseCookie(header: string | undefined): Record<string, string> {
    const out: Record<string, string> = {};
    if (!header) return out;
    for (const part of header.split(';')) {
        const i = part.indexOf('=');
        if (i < 0) continue;
        out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
    }
    return out;
}

export function isAllowlisted(pathname: string): boolean {
    return ALLOWLIST_EXACT.has(pathname) || ALLOWLIST_PREFIX.some((p) => pathname.startsWith(p));
}

export function sessionCookie(token: string, secure: boolean, maxAge?: number): string {
    const parts = [`${SESSION_COOKIE}=${token}`, 'HttpOnly', 'SameSite=Lax', 'Path=/'];
    if (secure) parts.push('Secure');
    if (maxAge !== undefined) parts.push(`Max-Age=${maxAge}`);
    return parts.join('; ');
}
