ALTER TABLE members ADD COLUMN removed_at timestamptz;

ALTER TABLE devices ADD COLUMN public_key text;

-- Opaque E2E key distribution: the server never sees the event key, only an envelope wrapped for one device.
CREATE TABLE key_envelopes (
  id text PRIMARY KEY,
  event_id text NOT NULL,
  target_device_id text NOT NULL UNIQUE,
  from_device_id text NOT NULL,
  wrapped_key text NOT NULL,
  meta jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX key_envelopes_event_idx ON key_envelopes (event_id);
