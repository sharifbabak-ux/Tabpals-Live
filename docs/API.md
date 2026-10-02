# TabPals API — مرجع کامل

Base URL (production): `https://api.tabpals.ir` — all JSON endpoints live under `/v1`. Request and response bodies are JSON (`Content-Type: application/json`). Timestamps in responses are ISO-8601 UTC strings.

## Conventions

- **Auth**: every endpoint except `POST /v1/events`, `POST /v1/invites/redeem` and `GET /health` needs `Authorization: Bearer <deviceToken>`. The token is returned **once** (event creation or invite redemption); store it securely on the device. The server keeps only its SHA-256.
- **IDs**: `eventId`, `memberId` match `[A-Za-z0-9_-]{1,64}` (client ULIDs / person ids). Op `id` and `entityId` match `[\w.:-]{1,128}`.
- **Errors**: always `{"error": {"code": "<code>", "message": "<Persian default>"}}`. Translate by `code`.
- **Non-members get `404 event-not-found`** (never 403) for any `/v1/events/:eventId/...` path, whether or not the event exists.
- **Rate limits** (`429 rate-limited`, standard `RateLimit-*` headers): 600 req/min/IP overall; 20 event creations/hour/IP; 10 *failed* redeems/15 min/IP; 120 ops POSTs/min/device.
- **Sizes**: JSON body ≤ 256 KB (≤ 8 MB for `POST ops`); each op ≤ 64 KB serialized; ≤ 500 ops per call.
- **CORS**: browsers must call from an origin in `ALLOWED_ORIGINS`.

## Roles and permission matrix

A member holds one or more of `admin`, `treasurer`, `member`. Roles are checked on the server on every write using the *current* roles (role changes apply immediately, no new token needed). Source of truth: `src/permissions.js`.

| Action | admin | treasurer | member |
|---|:-:|:-:|:-:|
| Read all ops / members of the event | ✔ | ✔ | ✔ |
| Write ledger ops: `events`, `persons`, `eventMembers`, `vouchers`, `statements`, `orderSessions`, `sessionMenuItems`, `orderLines`, `orderPersonTotals`, `sessionExtras` | ✔ | ✔ | ✘ |
| Write `memberProfile` op with `entityId` = own memberId | ✔ | ✔ | ✔ |
| Write `memberProfile` op for someone else | ✔ | ✘ | ✘ |
| Op `type: "purge"` on entity `events` | ✔ | ✘ | ✘ |
| Add member | ✔ | ✔ | ✘ |
| Change roles, create/revoke invites, view audit log, list all devices, revoke any device, purge event | ✔ | ✘ | ✘ |
| List own devices, revoke own device | ✔ | ✔ | ✔ |

Rules: an event always has ≥ 1 admin (`409 last-admin` when demoting the last one). Allowed op `type`s: `create, update, delete, archive, restore, purge, logSend`. Unknown entity/type is rejected with a reason.

`memberProfile` fields whose value is a string starting with `enc:` are opaque ciphertext; the server stores them verbatim and never logs or inspects them.

## Endpoints

### `POST /v1/events` — create a shared event (no auth)
Body:
```json
{ "eventId": "01J...", "title": "سفر شمال",
  "creator": {"memberId": "p1", "displayName": "علی"},
  "members": [{"memberId": "p2", "displayName": "سارا"}],
  "deviceLabel": "Android Chrome" }
```
`201` → `{ "deviceToken": "...", "deviceId": "..." }`. Creator gets roles `admin` + `treasurer`; others `member`. `members` may repeat the creator (ignored); ≤ 200 members; title ≤ 200 chars; names ≤ 80; label ≤ 40. Errors: `409 event-exists`, `400 invalid-field`, `413 payload-too-large`, `429 rate-limited`. Then upload existing history via `POST ops` in chunks.

### `POST /v1/events/:eventId/ops` — push ops (any member)
Body: `{ "ops": [ <client op>, ... ] }`, each op the full client operation:
```json
{ "id": "01J...", "entity": "vouchers", "entityId": "01J...", "type": "update",
  "changes": {"amount": {"before": 1000, "after": 1200}},
  "timestamp": 1760000000000, "deviceId": "client-device-id" }
```
`timestamp` is epoch ms or an ISO string. Response `200`:
```json
{ "accepted": [{"opId": "01J...", "seq": 41}],
  "rejected": [{"opId": "01J...", "reason": "forbidden-entity", "message": "..."}],
  "lastSeq": 57 }
```
Idempotent by op `id` per event: re-sending an already stored op returns it in `accepted` with its original `seq` and is not re-broadcast. `lastSeq` is the event's highest seq. Op rejection reasons: `bad-op`, `op-too-large`, `unknown-entity`, `unknown-type`, `forbidden-entity`, `forbidden-profile`, `forbidden-purge`. Rejected ops are never stored; don't retry them unchanged. Request-level errors: `400 invalid-field` (empty/missing `ops` or > 500), `413`, `429`.

### `GET /v1/events/:eventId/ops?after=<seq>&limit=<n>` — pull ops (any member)
`after` default 0; `limit` default 200, max 500. Response:
```json
{ "ops": [{"seq": 42, "serverTs": "2026-...Z", "memberId": "p1", "deviceId": "...", "op": { /* original client op */ }}],
  "hasMore": false, "lastSeq": 42 }
```
`lastSeq` = seq of the last returned op, or `after` if none. Loop while `hasMore`, passing `after=lastSeq`. Store `lastSeq` locally; call this after every socket reconnect.

### `GET /v1/me`
`{ eventId, memberId, roles, deviceId, eventTitle, displayName }` for the calling device.

### `GET /v1/events/:eventId/members`
`{ "members": [{memberId, displayName, createdAt, roles: [...], activeDevices: 1}] }`

### `POST /v1/events/:eventId/members` — admin/treasurer
Body `{memberId, displayName}` → `201 {memberId, displayName, roles: ["member"]}`. `409 member-exists`.

### `PUT /v1/events/:eventId/members/:memberId/roles` — admin
Body `{"roles": ["treasurer", "member"]}` (non-empty subset of the three roles) → `{memberId, roles}`. `409 last-admin`, `404 member-not-found`. Emits `roles-changed`.

### `POST /v1/events/:eventId/invites` — admin
Body `{memberId}` → `201 { inviteId, inviteToken, shortCode, expiresAt }`. Valid 7 days, single use. `inviteToken` goes into a link; `shortCode` is 8 chars from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` for manual entry (case, spaces and dashes are ignored on redeem). Both are shown only once.

### `DELETE /v1/events/:eventId/invites/:inviteId` — admin
Revokes → `{ok: true}`. `404 invite-not-found`.

### `POST /v1/invites/redeem` — no auth
Body `{ "inviteToken": "..." | "shortCode": "ABCD-2345", "deviceLabel": "iPhone Safari" }` → `{ eventId, memberId, roles, deviceToken, deviceId, eventTitle }`. Binds a new device to the invited member. Errors: `404 invite-not-found`, `409 invite-used`, `410 invite-expired`, `410 invite-revoked`, `429 rate-limited` (10 failed attempts / 15 min / IP).

### `GET /v1/events/:eventId/devices`
`{ "devices": [{deviceId, memberId, label, createdAt, lastSeenAt, revokedAt, current}] }`. Admin: all devices of the event; others: their own member's.

### `DELETE /v1/events/:eventId/devices/:deviceId` — admin or the device itself
Revokes (idempotent) → `{ok: true}`. The device's next request gets `401 device-revoked`; its sockets receive `device-revoked` and are disconnected. `403 forbidden` if a non-admin targets another member's device; `404 device-not-found`.

### `GET /v1/events/:eventId/audit?limit=<n>&before=<id>` — admin
Newest first, `limit` default 50, max 200. `{ "entries": [{id, actorMember, actorDevice, action, target, details, at}], "nextBefore": 123 | null }` — pass `nextBefore` as `before` for the next page. Actions: `event.created`, `member.added`, `roles.changed`, `invite.created`, `invite.redeemed`, `invite.revoked`, `device.revoked`. Details contain only ids/role names — never bank data or message content. (Purge deletes the audit log with everything else.)

### `DELETE /v1/events/:eventId` — admin
Deletes **all** rows of the event (ops, members, roles, devices, invites, audit) in one transaction → `{ok: true}`; sockets get `event-purged` and are disconnected. Afterwards every token of the event gets `401 unauthorized`.

### `GET /health` → `{status: "ok", time}`

## Realtime (Socket.IO)

Connect to the base URL (path `/socket.io`, transports `["websocket","polling"]`) with the device token in the handshake:
```js
const socket = io("https://api.tabpals.ir", { auth: { token: deviceToken } });
```
A rejected handshake fires `connect_error` with `err.data.code` = `unauthorized` or `device-revoked`. On success the server sends `ready` `{eventId, memberId, roles}` and joins the socket to its event room. Sockets are receive-only: write through `POST ops`.

| Event | Payload | When |
|---|---|---|
| `ready` | `{eventId, memberId, roles}` | after connect |
| `ops` | `{ops: [{seq, serverTs, memberId, deviceId, op}], lastSeq}` | newly accepted ops (also to the sender; skip ops you already know by `op.id`). Not sent for duplicates |
| `roles-changed` | `{memberId, roles}` | roles updated |
| `device-revoked` | `{deviceId}` | this device was revoked; socket then closes |
| `event-purged` | `{eventId}` | event deleted; socket then closes |

Catch-up: if `ops.lastSeq` leaves a gap versus your stored `lastSeq` (or after any reconnect), call `GET ops?after=<yourLastSeq>` until `hasMore` is false.

## Error codes

| HTTP | code | Meaning |
|---|---|---|
| 400 | `bad-request`, `bad-json`, `invalid-field` | malformed request / field |
| 401 | `unauthorized` | missing/unknown token |
| 401 | `device-revoked` | token belongs to a revoked device |
| 403 | `forbidden` | role does not allow it |
| 404 | `not-found`, `event-not-found`, `member-not-found`, `device-not-found`, `invite-not-found` | missing (or not a member) |
| 409 | `event-exists`, `member-exists`, `invite-used`, `last-admin` | conflict |
| 410 | `invite-expired`, `invite-revoked` | invite no longer valid |
| 413 | `payload-too-large` | body too big |
| 429 | `rate-limited` | slow down |
| 500 | `internal-error` | server error |

## Example (curl)
```sh
curl -X POST https://api.tabpals.ir/v1/events -H 'content-type: application/json' \
  -d '{"eventId":"EV1","title":"سفر","creator":{"memberId":"p1","displayName":"علی"},"deviceLabel":"Android Chrome"}'
# → {"deviceToken":"<T>","deviceId":"..."}
curl -X POST https://api.tabpals.ir/v1/events/EV1/ops -H "authorization: Bearer <T>" -H 'content-type: application/json' \
  -d '{"ops":[{"id":"OP1","entity":"vouchers","entityId":"V1","type":"create","changes":{},"timestamp":1760000000000,"deviceId":"d1"}]}'
curl https://api.tabpals.ir/v1/events/EV1/ops?after=0 -H "authorization: Bearer <T>"
```
