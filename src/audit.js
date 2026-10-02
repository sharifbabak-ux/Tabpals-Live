// details must never contain bank data or message content — callers pass only ids and role names.
export const audit = (q, eventId, actor, action, target, details = null) =>
  q.query(
    'INSERT INTO audit_log (event_id, actor_member, actor_device, action, target, details) VALUES ($1,$2,$3,$4,$5,$6)',
    [eventId, actor?.memberId ?? null, actor?.id ?? null, action, target ?? null, details ? JSON.stringify(details) : null],
  );
