-- name: FindingsByID :many
SELECT id, details
FROM finding
WHERE instance_id = ?
;

-- name: FindingsPageByID :many
SELECT id, details
FROM finding
WHERE instance_id = ?
ORDER BY id
LIMIT ?
OFFSET ?
;

-- name: CreateFinding :exec
INSERT INTO finding (instance_id, details)
    VALUES (?, ?)
;

-- name: UpdateFinding :one
UPDATE finding
SET
    details = ?,
    updated_at = ?
WHERE
    instance_id = ? AND
    id = ?
RETURNING *
;
