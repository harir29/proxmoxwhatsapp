import { createHash, createPublicKey, randomBytes, verify } from 'crypto';
import type { Db } from '../db/Db';
import type { Role, User } from '../db/UserStore';
import { loadOidcConfig, type OidcConfig } from './oidcConfig';

type Discovery = {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    jwks_uri: string;
    end_session_endpoint?: string;
};

type Jwk = JsonWebKey & { kid?: string; use?: string; alg?: string };
type Claims = {
    iss?: string;
    sub?: string;
    aud?: string | string[];
    azp?: string;
    exp?: number;
    iat?: number;
    nonce?: string;
    preferred_username?: string;
    email?: string;
    resource_access?: Record<string, { roles?: string[] }>;
    realm_access?: { roles?: string[] };
};

type PendingLogin = { nonce: string; verifier: string; returnTo: string; expiresAt: number };

const STATE_TTL_MS = 10 * 60 * 1000;

function randomUrlSafe(bytes = 32): string {
    return randomBytes(bytes).toString('base64url');
}

function sha256UrlSafe(value: string): string {
    return createHash('sha256').update(value).digest('base64url');
}

function safeReturnTo(value: string | null): string {
    if (!value || !value.startsWith('/') || value.startsWith('//')) return '/';
    return value;
}

function decodePart<T>(part: string): T {
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as T;
}

function usernameFromClaims(claims: Claims): string {
    const raw = claims.preferred_username || claims.email || claims.sub || '';
    const normalized = raw.trim().slice(0, 128);
    if (!normalized) throw new Error('OIDC token has no usable username');
    return normalized;
}

export class OidcService {
    private static instance?: OidcService;
    private readonly pending = new Map<string, PendingLogin>();
    private discoveryCache?: { value: Discovery; expiresAt: number };
    private jwksCache: { value: Jwk[]; expiresAt: number } | undefined;

    static getInstance(): OidcService {
        this.instance ??= new OidcService();
        return this.instance;
    }

    private config(db: Db): OidcConfig {
        const config = loadOidcConfig(db);
        if (!config) throw new Error('OIDC is not enabled');
        return config;
    }

    private async getJson<T>(url: string): Promise<T> {
        const response = await fetch(url, { signal: AbortSignal.timeout(10_000) });
        if (!response.ok) throw new Error(`OIDC request failed: HTTP ${response.status}`);
        return (await response.json()) as T;
    }

    private async discovery(config: OidcConfig): Promise<Discovery> {
        const now = Date.now();
        if (this.discoveryCache && this.discoveryCache.expiresAt > now) return this.discoveryCache.value;
        const value = await this.getJson<Discovery>(`${config.issuer}/.well-known/openid-configuration`);
        if (value.issuer !== config.issuer) throw new Error('OIDC discovery issuer mismatch');
        this.discoveryCache = { value, expiresAt: now + 60 * 60 * 1000 };
        return value;
    }

    async authorizationUrl(db: Db, returnToValue: string | null): Promise<string> {
        const config = this.config(db);
        const discovery = await this.discovery(config);
        const state = randomUrlSafe();
        const nonce = randomUrlSafe();
        const verifier = randomUrlSafe(48);
        this.pending.set(state, {
            nonce,
            verifier,
            returnTo: safeReturnTo(returnToValue),
            expiresAt: Date.now() + STATE_TTL_MS,
        });
        for (const [key, login] of this.pending) {
            if (login.expiresAt <= Date.now()) this.pending.delete(key);
        }
        const url = new URL(discovery.authorization_endpoint);
        url.searchParams.set('client_id', config.clientId);
        url.searchParams.set('redirect_uri', config.redirectUri);
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('scope', 'openid profile email');
        url.searchParams.set('state', state);
        url.searchParams.set('nonce', nonce);
        url.searchParams.set('code_challenge', sha256UrlSafe(verifier));
        url.searchParams.set('code_challenge_method', 'S256');
        return url.toString();
    }

    private async verifyIdToken(token: string, config: OidcConfig, expectedNonce: string): Promise<Claims> {
        const parts = token.split('.');
        if (parts.length !== 3) throw new Error('Malformed OIDC ID token');
        const header = decodePart<{ alg?: string; kid?: string }>(parts[0]!);
        if (header.alg !== 'RS256' || !header.kid) throw new Error('Unsupported OIDC signing algorithm');

        const discovery = await this.discovery(config);
        const now = Date.now();
        if (!this.jwksCache || this.jwksCache.expiresAt <= now) {
            const result = await this.getJson<{ keys: Jwk[] }>(discovery.jwks_uri);
            this.jwksCache = { value: result.keys, expiresAt: now + 60 * 60 * 1000 };
        }
        const jwk = this.jwksCache.value.find((candidate) => candidate.kid === header.kid);
        if (!jwk) {
            this.jwksCache = undefined;
            throw new Error('OIDC signing key not found');
        }
        const signed = Buffer.from(`${parts[0]}.${parts[1]}`);
        const signature = Buffer.from(parts[2]!, 'base64url');
        if (!verify('RSA-SHA256', signed, createPublicKey({ key: jwk, format: 'jwk' }), signature)) {
            throw new Error('Invalid OIDC ID token signature');
        }

        const claims = decodePart<Claims>(parts[1]!);
        const nowSeconds = Math.floor(Date.now() / 1000);
        const audience = Array.isArray(claims.aud) ? claims.aud : claims.aud ? [claims.aud] : [];
        if (claims.iss !== config.issuer) throw new Error('OIDC token issuer mismatch');
        if (!claims.sub) throw new Error('OIDC token subject missing');
        if (!audience.includes(config.clientId) && claims.azp !== config.clientId) {
            throw new Error('OIDC token audience mismatch');
        }
        if (typeof claims.exp !== 'number' || claims.exp <= nowSeconds - 30) throw new Error('OIDC token expired');
        if (typeof claims.iat === 'number' && claims.iat > nowSeconds + 60) throw new Error('OIDC token issued in future');
        if (claims.nonce !== expectedNonce) throw new Error('OIDC token nonce mismatch');
        return claims;
    }

    private roleFromClaims(claims: Claims, config: OidcConfig): Role {
        const roles = new Set([
            ...(claims.resource_access?.[config.clientId]?.roles || []),
            ...(claims.realm_access?.roles || []),
        ]);
        if (roles.has(config.adminRole)) return 'admin';
        if (roles.has(config.userRole)) return 'user';
        throw new Error('Account is not assigned an Android access role');
    }

    private provisionUser(db: Db, claims: Claims, config: OidcConfig): User {
        const subject = claims.sub!;
        const role = this.roleFromClaims(claims, config);
        let user = db.users.getByOidcIdentity(config.issuer, subject);
        if (!user) {
            const username = usernameFromClaims(claims);
            if (db.users.getByUsername(username)) {
                throw new Error(`Local username already exists and is not linked to this Keycloak account: ${username}`);
            }
            user = db.users.createOidc({ username, role, issuer: config.issuer, subject });
        } else if (user.role !== role) {
            db.users.setRole(user.id, role);
            user = db.users.getById(user.id)!;
        }
        if (user.disabled) throw new Error('Account is disabled');
        if (user.role === 'user' && db.deviceAccess.listForUser(user.id).length === 0) {
            const defaultDevice = config.defaultDevices[user.username];
            if (defaultDevice) db.deviceAccess.assign(user.id, defaultDevice, true);
        }
        db.users.setLastLogin(user.id, Date.now());
        return user;
    }

    async completeCallback(
        db: Db,
        code: string,
        state: string,
    ): Promise<{ user: User; returnTo: string; idToken: string }> {
        const pending = this.pending.get(state);
        this.pending.delete(state);
        if (!pending || pending.expiresAt <= Date.now()) throw new Error('OIDC login state is invalid or expired');
        const config = this.config(db);
        const discovery = await this.discovery(config);
        const body = new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: config.redirectUri,
            client_id: config.clientId,
            client_secret: config.clientSecret,
            code_verifier: pending.verifier,
        });
        const response = await fetch(discovery.token_endpoint, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body,
            signal: AbortSignal.timeout(10_000),
        });
        if (!response.ok) throw new Error(`OIDC token exchange failed: HTTP ${response.status}`);
        const tokens = (await response.json()) as { id_token?: string };
        if (!tokens.id_token) throw new Error('OIDC token response did not contain an ID token');
        const claims = await this.verifyIdToken(tokens.id_token, config, pending.nonce);
        return { user: this.provisionUser(db, claims, config), returnTo: pending.returnTo, idToken: tokens.id_token };
    }

    async logoutUrl(db: Db): Promise<string> {
        const config = this.config(db);
        const discovery = await this.discovery(config);
        if (!discovery.end_session_endpoint) return config.postLogoutRedirectUri;
        const url = new URL(discovery.end_session_endpoint);
        url.searchParams.set('client_id', config.clientId);
        url.searchParams.set('post_logout_redirect_uri', config.postLogoutRedirectUri);
        return url.toString();
    }
}
