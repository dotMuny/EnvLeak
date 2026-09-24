-- UUIDs and base64 payloads that are data, not credentials.
INSERT INTO tenants (id, name) VALUES
  ('3f9a1c7e-5b2d-8460-af13-ce92b7d045e6', 'acme'),
  ('c81af239-3f9a-1c7e-5b2d-8460af13ce92', 'globex');

INSERT INTO assets (id, payload) VALUES
  (1, 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==');
