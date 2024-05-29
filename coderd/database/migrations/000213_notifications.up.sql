CREATE TYPE notification_message_status AS ENUM (
    'pending',
    'enqueued',
    'sent',
    'canceled',
    'failed',
    'inhibited',
    'unknown'
    );

CREATE TABLE notification_templates
(
    id             uuid                 NOT NULL,
    name           text                 NOT NULL,
    enabled        boolean DEFAULT TRUE NOT NULL,
    title_template text                 NOT NULL,
    body_template  text                 NOT NULL,
    "group"        text,
    PRIMARY KEY (id),
    UNIQUE (name)
);

COMMENT ON TABLE notification_templates IS 'Templates from which to create notification messages.';

CREATE TABLE notification_messages
(
    id                       uuid                        NOT NULL,
    notification_template_id uuid                        NOT NULL,
    status                   notification_message_status NOT NULL DEFAULT 'pending'::notification_message_status,
    status_reason            text,
    created_by               text                        NOT NULL,
    input                    jsonb,
    attempt_count            int,
    created_at               timestamp with time zone    NOT NULL,
    updated_at               timestamp with time zone,
    leased_until             timestamp with time zone,
    next_retry_after         timestamp with time zone,
    sent_at                  timestamp with time zone,
    failed_at                timestamp with time zone,
    targets                  uuid[],
    dedupe_hash              text                        NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (notification_template_id) REFERENCES notification_templates (id) ON DELETE CASCADE
);

CREATE INDEX idx_notification_messages_status ON notification_messages (status);

CREATE TABLE notification_preferences
(
    id                       uuid NOT NULL,
    notification_template_id uuid NOT NULL,
    disabled                 boolean,
    user_id                  uuid,
    org_id                   uuid,
    PRIMARY KEY (id),
    FOREIGN KEY (notification_template_id) REFERENCES notification_templates (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE
);
