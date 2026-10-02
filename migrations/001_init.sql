CREATE TABLE events (
  id text PRIMARY KEY,
  title text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by_member text NOT NULL,
  deleted_at timestamptz
);

CREATE TABLE members (
  event_id text NOT NULL REFERENCES events(id),
  member_id text NOT NULL,
  display_name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (event_id, member_id)
);

CREATE TABLE member_roles (
  event_id text NOT NULL,
  member_id text NOT NULL,
  role text NOT NULL CHECK (role IN ('admin', 'treasurer', 'member')),
  PRIMARY KEY (event_id, member_id, role),
  FOREIGN KEY (event_id, member_id) REFERENCES members(event_id, member_id)
);

CREATE TABLE devices (
  id text PRIMARY KEY,
  event_id text NOT NULL,
  member_id text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  label text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  FOREIGN KEY (event_id, member_id) REFERENCES members(event_id, member_id)
);
CREATE INDEX devices_event_idx ON devices (event_id);

CREATE TABLE invites (
  id text PRIMARY KEY,
  event_id text NOT NULL,
  member_id text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  short_code_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  used_by_device text,
  created_by_member text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  FOREIGN KEY (event_id, member_id) REFERENCES members(event_id, member_id)
);
CREATE INDEX invites_event_idx ON invites (event_id);

CREATE TABLE ops (
  seq bigserial PRIMARY KEY,
  event_id text NOT NULL REFERENCES events(id),
  op_id text NOT NULL,
  device_id text NOT NULL,
  member_id text NOT NULL,
  entity text NOT NULL,
  entity_id text NOT NULL,
  type text NOT NULL,
  payload jsonb NOT NULL,
  client_ts timestamptz NOT NULL,
  server_ts timestamptz NOT NULL DEFAULT now(),
  UNIQUE (event_id, op_id)
);
CREATE INDEX ops_event_seq_idx ON ops (event_id, seq);

CREATE TABLE audit_log (
  id bigserial PRIMARY KEY,
  event_id text NOT NULL,
  actor_member text,
  actor_device text,
  action text NOT NULL,
  target text,
  details jsonb,
  at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_event_idx ON audit_log (event_id, id);
