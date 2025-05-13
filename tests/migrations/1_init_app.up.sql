INSERT INTO apps (id, name, secret)
VALUES (1, 'test', 'secret')
ON CONFLICT DO NOTHING;