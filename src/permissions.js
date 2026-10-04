// Single source of truth for who may do what. See docs/API.md for the human-readable matrix.

export const ROLES = ['admin', 'treasurer', 'member'];

export const OP_TYPES = ['create', 'update', 'delete', 'archive', 'restore', 'purge', 'logSend'];

// Sensitive field values may be end-to-end encrypted opaque strings; the server stores them verbatim
// (subject to the normal op size limit) and never inspects or logs them.
export const ENC_PREFIX = 'enc:v1:';
export const isEncryptedValue = (v) => typeof v === 'string' && v.startsWith(ENC_PREFIX);

// Writable only by treasurer or admin. Any of their fields may carry encrypted values.
export const LEDGER_ENTITIES = [
  'events',
  'persons',
  'eventMembers',
  'vouchers',
  'statements',
  'orderSessions',
  'sessionMenuItems',
  'orderLines',
  'orderPersonTotals',
  'sessionExtras',
];

// Restricted entity. Writable by the owning member (entityId === own memberId), treasurer and admin.
// Readable (GET ops and socket `ops`) by the same set of devices only.
export const PROFILE_ENTITY = 'memberProfile';

export const ENTITIES = [...LEDGER_ENTITIES, PROFILE_ENTITY];

// Non-op actions.
export const ACTION_ROLES = {
  'ops.read': ROLES,
  'members.read': ROLES,
  'members.add': ['admin', 'treasurer'],
  'roles.set': ['admin'],
  'invites.manage': ['admin'],
  'members.remove': ['admin'], // also covers restore
  'devices.listAll': ['admin'],
  'devices.revokeAny': ['admin'], // a device may always revoke itself
  'audit.read': ['admin'],
  'event.purge': ['admin'],
};

export const hasAny = (roles, allowed) => allowed.some((r) => roles.includes(r));
export const can = (roles, action) => hasAny(roles, ACTION_ROLES[action] || []);

const canAccessProfile = (actor, ownerId) => ownerId === actor.memberId || hasAny(actor.roles, ['admin', 'treasurer']);

/** Whether a device (with current roles) may receive a stored op. Only memberProfile is restricted. */
export const canReadOp = (actor, { entity, entityId }) => entity !== PROFILE_ENTITY || canAccessProfile(actor, entityId);

/**
 * @param {{memberId: string, roles: string[]}} actor
 * @param {{entity: string, entityId: string, type: string}} op
 * @returns {{ok: true} | {ok: false, reason: string}}
 */
export function checkOp(actor, op) {
  if (!ENTITIES.includes(op.entity)) return { ok: false, reason: 'unknown-entity' };
  if (!OP_TYPES.includes(op.type)) return { ok: false, reason: 'unknown-type' };
  const isAdmin = actor.roles.includes('admin');
  if (op.entity === PROFILE_ENTITY) {
    return canAccessProfile(actor, op.entityId) ? { ok: true } : { ok: false, reason: 'forbidden-profile' };
  }
  if (op.entity === 'events' && op.type === 'purge' && !isAdmin) {
    return { ok: false, reason: 'forbidden-purge' };
  }
  return hasAny(actor.roles, ['admin', 'treasurer']) ? { ok: true } : { ok: false, reason: 'forbidden-entity' };
}
