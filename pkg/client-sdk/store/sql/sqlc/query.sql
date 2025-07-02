-- name: InsertVtxo :exec
INSERT INTO vtxo (
    txid, vout, script, amount, commitment_txids, spent_by, spent, preconfirmed, expires_at, created_at, swept, unrolled, settled_by, ark_txid
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateVtxo :exec
UPDATE vtxo
SET
    spent = true,
    spent_by = :spent_by,
    settled_by = :settled_by,
    ark_txid = :ark_txid
WHERE txid = :txid AND vout = :vout;

-- name: SelectAllVtxos :many
SELECT * from vtxo;

-- name: SelectVtxo :one
SELECT *
FROM vtxo
WHERE txid = :txid AND vout = :vout;

-- name: CleanVtxos :exec
DELETE FROM vtxo;

-- name: InsertTx :exec
INSERT INTO tx (
    txid, txid_type, amount, type, settled, created_at, hex, settled_by
) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateTx :exec
UPDATE tx
SET
    created_at     = COALESCE(sqlc.narg(created_at),     created_at),
    settled    = COALESCE(sqlc.narg(settled),    settled),
    settled_by    = COALESCE(sqlc.narg(settled_by),    settled_by)
WHERE txid = :txid; 

-- name: ReplaceTx :exec
UPDATE tx
SET    txid       = :new_txid,
       txid_type  = :txid_type,
       amount     = :amount,
       type       = :type,
       settled    = :settled,
       settled_by    = :settled_by,
       created_at = :created_at,
       hex        = :hex
WHERE  txid = :old_txid;

-- name: SelectAllTxs :many
SELECT * FROM tx;

-- name: SelectTxs :many
SELECT * FROM tx
WHERE txid IN (sqlc.slice('txids'));

-- name: CleanTxs :exec
DELETE FROM tx;