-- name: InsertNotificationTemplate :one
INSERT INTO notification_templates (id, name, enabled, title_template, body_template, "group")
VALUES ($1,
        $2,
        $3,
        $4,
        $5,
        $6)
RETURNING *;

-- name: EnqueueNotificationMessage :one
INSERT INTO notification_messages (id, notification_template_id, input, targets, dedupe_hash, created_by)
VALUES ($1,
        $2,
        $3,
        $4,
        $5,
        $6)
RETURNING *;

-- Acquires the lease for a given count of notification messages that aren't already locked, or ones which are leased
-- but have exceeded their lease period.
--
-- SKIP LOCKED is used to jump over locked rows. This prevents
-- multiple notifiers from acquiring the same messages. See:
-- https://www.postgresql.org/docs/9.5/sql-select.html#SQL-FOR-UPDATE-SHARE
-- name: AcquireNotificationMessages :many
UPDATE
    notification_messages
SET updated_at    = NOW(),
    status        = 'enqueued'::notification_message_status,
    status_reason = 'Enqueued by notifier ' || sqlc.arg('notifier_id')::uuid,
    leased_until  = sqlc.arg('leased_until')::time
WHERE id = (SELECT nm.id,
                   nt.id,
                   nt.title_template,
                   nt.body_template,
                   nm.input
            FROM notification_messages AS nm
                     LEFT JOIN notification_templates AS nt ON (nm.notification_template_id = nt.id)
                     LEFT JOIN notification_preferences np ON (np.notification_template_id = nt.id)
            WHERE (
                (
                    -- message is in acquirable states
                    nm.status NOT IN (
                        -- don't enqueue currently enqueued messages
                                      'enqueued'::notification_message_status,
                        -- don't enqueue inhibited messages (these will get deleted)
                                      'inhibited'::notification_message_status
                        )
                    )
                    -- or somehow the message was left in enqueued for longer than its lease period
                    OR (
                    nm.status = 'enqueued'::notification_message_status
                        AND nm.leased_until < NOW()
                    )
                )
              -- if set, do not retry until we've exceeded the wait time
              AND (nm.next_retry_after IS NOT NULL AND nm.next_retry_after < NOW())
              -- only enqueue if user/org has not disabled this template
              AND (np.disabled = FALSE
                AND (np.user_id = sqlc.arg('user_id')::uuid OR np.org_id = sqlc.arg('org_id')::uuid)
                )
            ORDER BY nm.created_at ASC
                FOR UPDATE
                    SKIP LOCKED
            LIMIT sqlc.arg('count'))
RETURNING *;

-- name: MarkNotificationMessageFailed :one
UPDATE notification_messages
SET updated_at       = NOW(),
    attempt_count    = attempt_count + 1,
    status           = sqlc.arg('status'),
    status_reason    = sqlc.narg('reason'),
    failed_at        = sqlc.arg('failed_at')::time,
    next_retry_after = sqlc.narg('next_retry_after')::time -- optional: retries may have been exceeded
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: MarkNotificationMessagesInhibited :one
UPDATE notification_messages
SET updated_at       = NOW(),
    status           = 'inhibited'::notification_message_status,
    status_reason    = sqlc.narg('reason'),
    sent_at          = NULL,
    failed_at        = NULL,
    next_retry_after = NULL
WHERE notification_template_id = sqlc.arg('notification_template_id')::uuid
  AND sqlc.arg('user_or_org_id')::uuid = ANY (UNNEST(targets))
RETURNING *;

-- name: MarkNotificationMessageSent :one
UPDATE notification_messages
SET updated_at       = NOW(),
    status           = 'sent'::notification_message_status,
    sent_at          = sqlc.arg('sent_at')::time,
    leased_until     = NULL,
    next_retry_after = NULL
WHERE id = sqlc.arg('id')
RETURNING *;

-- Delete all notification messages which have not been updated for over a week.
-- Delete all sent or inhibited messages which are over a day old.
-- name: DeleteOldNotificationMessages :exec
DELETE
FROM notification_messages
WHERE id =
      (SELECT id
       FROM notification_messages AS nested
       WHERE nested.updated_at < NOW() - INTERVAL '7 days'
          OR (
           nested.status = 'sent'::notification_message_status AND nested.sent_at < (NOW() - INTERVAL '1 days')
           )
          OR (
           nested.status = 'inhibited'::notification_message_status AND
           nested.updated_at < (NOW() - INTERVAL '1 days')
           )
           FOR UPDATE SKIP LOCKED); -- ensure we don't clash with the notifier