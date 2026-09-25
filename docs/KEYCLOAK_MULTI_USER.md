# Keycloak multi-user reDroid access

This deployment uses the existing `wsscrcpy_sid` application session after a
Keycloak Authorization Code + PKCE login. OIDC is disabled unless `oidc.json`
exists beside `wsscrcpy.db` and contains `"enabled": true`.

## Keycloak client

- Realm: `androidwsp`
- Client ID: `ws-scrcpy-android`
- Client authentication: enabled (confidential client)
- Standard flow: enabled
- PKCE method: `S256`
- Valid redirect URI:
  `https://android-fast.wsprime.net/api/auth/oidc/callback`
- Valid post-logout redirect URI: `https://android-fast.wsprime.net/*`
- Web origin: `https://android-fast.wsprime.net`
- Client roles: `android-admin`, `android-user`

Assign exactly one of those roles to each Keycloak account. The ID token must
contain client roles in Keycloak's standard `resource_access` claim (realm roles
with the same names are also accepted).

## Server configuration

Create `oidc.json` next to the live `wsscrcpy.db`, owned by root and mode 600:

```json
{
  "enabled": true,
  "issuer": "https://auth.winstonefx.com/realms/androidwsp",
  "clientId": "ws-scrcpy-android",
  "clientSecret": "REPLACE_ON_THE_SERVER",
  "redirectUri": "https://android-fast.wsprime.net/api/auth/oidc/callback",
  "postLogoutRedirectUri": "https://android-fast.wsprime.net/",
  "adminRole": "android-admin",
  "userRole": "android-user",
  "defaultDevices": {
    "user1": "127.0.0.1:5555",
    "user2": "127.0.0.1:5556",
    "user3": "127.0.0.1:5557",
    "user4": "127.0.0.1:5558"
  }
}
```

The `defaultDevices` map assigns a user's device on their first successful
login. An administrator may subsequently manage assignments with:

- `GET /api/users`
- `GET /api/users/:id/devices`
- `PUT /api/users/:id/devices` with `{ "udid": "127.0.0.1:5555", "isDefault": true }`
- `DELETE /api/users/:id/devices` with `{ "udid": "127.0.0.1:5555" }`

Administrators can see and control every device. A normal user receives only
their assigned device in tracker events; direct stream, probe, shell, file,
settings, power, label, and delete operations are independently checked on the
server. Network scanning is administrator-only.
