-- name: UpsertTransaction :exec
INSERT INTO tx (
    tx, round_id, type, position, txid, children
) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(txid) DO UPDATE SET
    tx = EXCLUDED.tx,
    round_id = EXCLUDED.round_id,
    type = EXCLUDED.type,
    position = EXCLUDED.position,
    txid = EXCLUDED.txid,
    children = EXCLUDED.children;

-- name: UpsertRound :exec
INSERT INTO round (
    id,
    starting_timestamp,
    ending_timestamp,
    ended, failed,
    stage_code,
    txid,
    connector_address,
    version,
    swept,
    vtxo_tree_expiration
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    starting_timestamp = EXCLUDED.starting_timestamp,
    ending_timestamp = EXCLUDED.ending_timestamp,
    ended = EXCLUDED.ended,
    failed = EXCLUDED.failed,
    stage_code = EXCLUDED.stage_code,
    txid = EXCLUDED.txid,
    connector_address = EXCLUDED.connector_address,
    version = EXCLUDED.version,
    swept = EXCLUDED.swept,
    vtxo_tree_expiration = EXCLUDED.vtxo_tree_expiration;

-- name: GetTxsByTxid :many
SELECT
    tx.txid,
    tx.tx AS data
FROM tx
WHERE tx.txid IN (sqlc.slice('ids1'))
UNION
SELECT
    virtual_tx.txid,
    virtual_tx.tx AS data
FROM virtual_tx
WHERE virtual_tx.txid IN (sqlc.slice('ids2'))
UNION
SELECT
    checkpoint_tx.txid,
    checkpoint_tx.tx AS data
FROM checkpoint_tx
WHERE checkpoint_tx.txid IN (sqlc.slice('ids3'));

-- name: UpsertTxRequest :exec
INSERT INTO tx_request (id, round_id, proof, message) VALUES (?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    round_id = EXCLUDED.round_id,
    proof = EXCLUDED.proof,
    message = EXCLUDED.message;

-- name: UpsertReceiver :exec
INSERT INTO receiver (request_id, pubkey, onchain_address, amount) VALUES (?, ?, ?, ?)
ON CONFLICT(request_id, pubkey, onchain_address) DO UPDATE SET
    amount = EXCLUDED.amount,
    pubkey = EXCLUDED.pubkey,
    onchain_address = EXCLUDED.onchain_address;

-- name: UpdateVtxoRequestId :exec
UPDATE vtxo SET request_id = ? WHERE txid = ? AND vout = ?;

-- name: SelectRoundWithRoundId :many
SELECT sqlc.embed(round),
       sqlc.embed(round_request_vw),
       sqlc.embed(round_tx_vw),
       sqlc.embed(request_receiver_vw),
       sqlc.embed(request_vtxo_vw)
FROM round
         LEFT OUTER JOIN round_request_vw ON round.id=round_request_vw.round_id
         LEFT OUTER JOIN round_tx_vw ON round.id=round_tx_vw.round_id
         LEFT OUTER JOIN request_receiver_vw ON round_request_vw.id=request_receiver_vw.request_id
         LEFT OUTER JOIN request_vtxo_vw ON round_request_vw.id=request_vtxo_vw.request_id
WHERE round.id = ?;

-- name: SelectRoundWithRoundTxId :many
SELECT sqlc.embed(round),
       sqlc.embed(round_request_vw),
       sqlc.embed(round_tx_vw),
       sqlc.embed(request_receiver_vw),
       sqlc.embed(request_vtxo_vw)
FROM round
         LEFT OUTER JOIN round_request_vw ON round.id=round_request_vw.round_id
         LEFT OUTER JOIN round_tx_vw ON round.id=round_tx_vw.round_id
         LEFT OUTER JOIN request_receiver_vw ON round_request_vw.id=request_receiver_vw.request_id
         LEFT OUTER JOIN request_vtxo_vw ON round_request_vw.id=request_vtxo_vw.request_id
WHERE round.txid = ?;

-- name: SelectUnsweptRoundsTxid :many
SELECT round.txid FROM round
WHERE round.swept = false AND round.ended = true AND round.failed = false;

-- name: GetRoundStats :one
SELECT
    r.swept,
    r.starting_timestamp,
    r.ending_timestamp,
    (
        SELECT COALESCE(SUM(amount), 0)
        FROM (
            SELECT DISTINCT v2.*
            FROM vtxo v2
                    JOIN tx_request req2 ON req2.id = v2.request_id
            WHERE req2.round_id = r.id
        ) as tx_req_inputs_amount
    ) AS total_forfeit_amount,
    (
        SELECT COALESCE(COUNT(v3.txid), 0)
        FROM vtxo v3
                 JOIN tx_request req3 ON req3.id = v3.request_id
        WHERE req3.round_id = r.id
    ) AS total_input_vtxos,
    (
        SELECT COALESCE(SUM(amount), 0)
        FROM (
            SELECT DISTINCT rr.*
            FROM receiver rr
                JOIN tx_request req4 ON req4.id = rr.request_id
            WHERE req4.round_id = r.id
            AND (rr.onchain_address = '' OR rr.onchain_address IS NULL)
        ) AS tx_req_outputs_amount
    ) AS total_batch_amount,
    (
        SELECT COUNT(*)
        FROM tx t
        WHERE t.round_id = r.id
          AND t.type = 'tree'
          AND TRIM(COALESCE(t.children, '')) = ''
    ) AS total_output_vtxos,
    (
        SELECT MAX(v.expire_at)
        FROM vtxo_vw v
        WHERE v.round_tx = r.txid
    ) AS expires_at
FROM round r
WHERE r.txid = ?;

-- name: GetRoundForfeitTxs :many
SELECT tx.* FROM round
LEFT OUTER JOIN tx ON round.id=tx.round_id
WHERE round.txid = ? AND tx.type = 'forfeit';

-- name: GetRoundConnectorTreeTxs :many
SELECT tx.* FROM round
LEFT OUTER JOIN tx ON round.id=tx.round_id
WHERE round.txid = ? AND tx.type = 'connector';

-- name: GetSpendableVtxosWithPubKey :many
SELECT vtxo_vw.* FROM vtxo_vw
WHERE vtxo_vw.pubkey = ? AND vtxo_vw.spent = false AND vtxo_vw.swept = false;

-- name: SelectSweptRoundsConnectorAddress :many
SELECT round.connector_address FROM round
WHERE round.swept = true AND round.failed = false AND round.ended = true AND round.connector_address <> '';

-- name: SelectRoundIdsInRange :many
SELECT id FROM round WHERE starting_timestamp > ? AND starting_timestamp < ?;

-- name: SelectRoundIds :many
SELECT id FROM round;

-- name: UpsertVtxo :exec
INSERT INTO vtxo (txid, vout, pubkey, amount, round_tx, settled_by, spent_by, spent, redeemed, swept, expire_at, created_at, preconfirmed, ark_txid)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(txid, vout) DO UPDATE SET
    pubkey = EXCLUDED.pubkey,
    amount = EXCLUDED.amount,
    round_tx = EXCLUDED.round_tx,
    settled_by = EXCLUDED.settled_by,
    spent_by = EXCLUDED.spent_by,
    spent = EXCLUDED.spent,
    redeemed = EXCLUDED.redeemed,
    swept = EXCLUDED.swept,
    expire_at = EXCLUDED.expire_at,
    created_at = EXCLUDED.created_at,
    ark_txid = EXCLUDED.ark_txid,
    preconfirmed = EXCLUDED.preconfirmed;

-- name: InsertVtxoCommitmentTxid :exec
INSERT INTO vtxo_commitment_txid(vtxo_txid, vtxo_vout, commitment_txid) VALUES (?, ?, ?);

-- name: SelectSweepableVtxos :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw
WHERE redeemed = false AND swept = false;

-- name: SelectNotRedeemedVtxos :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw
WHERE redeemed = false;

-- name: SelectNotRedeemedVtxosWithPubkey :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw
WHERE redeemed = false AND pubkey = ?;

-- name: SelectVtxoByOutpoint :one
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw
WHERE txid = ? AND vout = ?;

-- name: SelectAllVtxos :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw;

-- name: SelectVtxosByRoundTxid :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw
WHERE round_tx = ?;

-- name: MarkVtxoAsRedeemed :exec
UPDATE vtxo SET redeemed = true WHERE txid = ? AND vout = ?;

-- name: MarkVtxoAsSwept :exec
UPDATE vtxo SET swept = true WHERE txid = ? AND vout = ?;

-- name: MarkVtxoAsSettled :exec
UPDATE vtxo SET spent = true, spent_by = ?, settled_by = ? WHERE txid = ? AND vout = ?;

-- name: MarkVtxoAsSpent :exec
UPDATE vtxo SET spent = true, spent_by = ?, ark_txid = ? WHERE txid = ? AND vout = ?;

-- name: UpdateVtxoExpireAt :exec
UPDATE vtxo SET expire_at = ? WHERE txid = ? AND vout = ?;

-- name: InsertMarketHour :one
INSERT INTO market_hour (
    start_time,
    end_time,
    period,
    round_interval,
    updated_at
) VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateMarketHour :one
UPDATE market_hour
SET start_time = ?,
    end_time = ?,
    period = ?,
    round_interval = ?,
    updated_at = ?
WHERE id = ?
RETURNING *;

-- name: GetLatestMarketHour :one
SELECT * FROM market_hour ORDER BY updated_at DESC LIMIT 1;

-- name: SelectTreeTxsWithRoundTxid :many
SELECT tx.* FROM round
LEFT OUTER JOIN tx ON round.id=tx.round_id
WHERE round.txid = ? AND tx.type = 'tree';

-- name: SelectVtxosWithPubkeys :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE pubkey IN (sqlc.slice('pubkey'));

-- name: GetExistingRounds :many
SELECT txid FROM round WHERE txid IN (sqlc.slice('txids'));

-- name: SelectLeafVtxosByRoundTxid :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw
WHERE round_tx = ? AND (redeem_tx IS NULL or redeem_tx = '');

-- name: UpsertVirtualTx :exec
INSERT INTO virtual_tx (
    txid, tx, starting_timestamp, ending_timestamp, expiry_timestamp, fail_reason, stage_code
) VALUES (@txid, @tx, @starting_timestamp, @ending_timestamp, @expiry_timestamp, @fail_reason, @stage_code)
    ON CONFLICT(txid) DO UPDATE SET
    tx = EXCLUDED.tx,
    starting_timestamp = EXCLUDED.starting_timestamp,
    ending_timestamp = EXCLUDED.ending_timestamp,
    expiry_timestamp = EXCLUDED.expiry_timestamp,
    fail_reason = EXCLUDED.fail_reason,
    stage_code = EXCLUDED.stage_code;

-- name: UpsertCheckpointTx :exec
INSERT INTO checkpoint_tx (
    txid, tx, commitment_txid, is_root_commitment_tx, virtual_txid
) VALUES (@txid, @tx, @commitment_txid, @is_root_commitment_tx, @virtual_txid)
    ON CONFLICT(txid) DO UPDATE SET
    tx = EXCLUDED.tx,
    commitment_txid = EXCLUDED.commitment_txid,
    is_root_commitment_tx = EXCLUDED.is_root_commitment_tx,
    virtual_txid = EXCLUDED.virtual_txid;

-- name: SelectVirtualTxWithTxId :many
SELECT  sqlc.embed(virtual_tx_checkpoint_tx_vw)
FROM virtual_tx_checkpoint_tx_vw WHERE txid = @txid;