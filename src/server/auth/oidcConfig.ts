import * as fs from 'fs';
import * as path from 'path';
import type { Db } from '../db/Db';

export interface OidcConfig {
    enabled: boolean;
    issuer: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    postLogoutRedirectUri: string;
    adminRole: string;
    userRole: string;
    defaultDevices: Record<string, string>;
}

type OidcConfigFile = Partial<OidcConfig>;

export function oidcConfigPath(db: Db): string {
    return path.join(path.dirname(db.dbPath), 'oidc.json');
}

export function loadOidcConfig(db: Db): OidcConfig | undefined {
    const file = oidcConfigPath(db);
    if (!fs.existsSync(file)) return undefined;
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as OidcConfigFile;
    if (parsed.enabled !== true) return undefined;
    const required = ['issuer', 'clientId', 'clientSecret', 'redirectUri', 'postLogoutRedirectUri'] as const;
    for (const key of required) {
        if (typeof parsed[key] !== 'string' || parsed[key].length === 0) {
            throw new Error(`OIDC configuration ${file}: ${key} is required`);
        }
    }
    return {
        enabled: true,
        issuer: parsed.issuer!.replace(/\/$/, ''),
        clientId: parsed.clientId!,
        clientSecret: parsed.clientSecret!,
        redirectUri: parsed.redirectUri!,
        postLogoutRedirectUri: parsed.postLogoutRedirectUri!,
        adminRole: parsed.adminRole || 'android-admin',
        userRole: parsed.userRole || 'android-user',
        defaultDevices:
            parsed.defaultDevices && typeof parsed.defaultDevices === 'object' ? parsed.defaultDevices : {},
    };
}

export function isOidcEnabled(db: Db): boolean {
    return loadOidcConfig(db) !== undefined;
}
