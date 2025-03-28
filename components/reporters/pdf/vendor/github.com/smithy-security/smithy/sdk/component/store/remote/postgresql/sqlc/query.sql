-- name: FindingsByID :many
SELECT id, details
    FROM finding
    WHERE instance_id = $1
    ORDER BY id ASC
;

-- name: CreateFindings :exec
INSERT INTO finding (instance_id, details) VALUES (
unnest(@instance_id_array::uuid[]),
unnest(@details_array::jsonb[])
);

-- name: UpdateFinding :exec
UPDATE finding
SET
    details = $1,
    updated_at = $2
WHERE
    instance_id = $3 AND id = $4
RETURNING *;
