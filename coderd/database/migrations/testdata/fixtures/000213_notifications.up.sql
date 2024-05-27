-- TODO: add more fixtures

DO
$$
	DECLARE
		template text;
	BEGIN
		SELECT 'You successfully did {{.thing}}!' INTO template;

		INSERT INTO notification_templates (id, name, enabled, title_template, body_template, "group")
		VALUES ('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 'A', TRUE, template, template, 'Group 1'),
			   ('b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12', 'B', TRUE, template, template, 'Group 1'),
			   ('c0eebc99-9c0b-4ef8-bb6d-6bb9bd380a13', 'C', TRUE, template, template, 'Group 2');

	END
$$;
