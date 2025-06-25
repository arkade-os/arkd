-- name: UpsertTransaction :exec
INSERT INTO tx (
    tx, round_id, type, position, txid, children
) VALUES (@tx, @round_id, @type, @position, @txid, @children)
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
    connector_address,
    version,
    swept,
    vtxo_tree_expiration
) VALUES (@id, @starting_timestamp, @ending_timestamp, @ended, @failed, @stage_code, @connector_address, @version, @swept, @vtxo_tree_expiration)
    ON CONFLICT(id) DO UPDATE SET
    starting_timestamp = EXCLUDED.starting_timestamp,
    ending_timestamp = EXCLUDED.ending_timestamp,
    ended = EXCLUDED.ended,
    failed = EXCLUDED.failed,
    stage_code = EXCLUDED.stage_code,
    connector_address = EXCLUDED.connector_address,
    version = EXCLUDED.version,
    swept = EXCLUDED.swept,
    vtxo_tree_expiration = EXCLUDED.vtxo_tree_expiration;


-- name: GetTxsByTxid :many
SELECT
    tx.txid,
    tx.tx AS data
FROM tx
WHERE tx.txid = ANY($1::varchar[]);

-- name: UpsertTxRequest :exec
INSERT INTO tx_request (id, round_id) VALUES (@id, @round_id)
    ON CONFLICT(id) DO UPDATE SET round_id = EXCLUDED.round_id;

-- name: UpsertReceiver :exec
INSERT INTO receiver (request_id, pubkey, onchain_address, amount) VALUES (@request_id, @pubkey, @onchain_address, @amount)
    ON CONFLICT(request_id, pubkey, onchain_address) DO UPDATE SET
    amount = EXCLUDED.amount,
    pubkey = EXCLUDED.pubkey,
    onchain_address = EXCLUDED.onchain_address;

-- name: UpdateVtxoRequestId :exec
UPDATE vtxo SET request_id = @request_id WHERE txid = @txid AND vout = @vout;

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
WHERE round.id = @id;

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
WHERE round.id = (
    SELECT round_id FROM round_tx_vw tx WHERE tx.txid = @txid and tx.type = 'commitment'
);

-- name: SelectExpiredRoundsTxid :many
SELECT txid FROM round_commitment_tx_vw r
WHERE r.swept = false AND r.ended = true AND r.failed = false;

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
          AND COALESCE(t.children, '{}'::jsonb) = '{}'::jsonb
    ) AS total_output_vtxos,
    (
        SELECT MAX(v.expire_at)
        FROM vtxo_vw v
        WHERE v.commitment_txid = r.txid
    ) AS expires_at
FROM round_commitment_tx_vw r
WHERE r.txid = @txid;

-- name: SelectUnsweptRoundsTxid :many
SELECT txid FROM round_commitment_tx_vw r
WHERE r.swept = false AND r.ended = true AND r.failed = false;

-- name: GetRoundForfeitTxs :many
SELECT t.* FROM tx t
WHERE t.round_id IN (SELECT rctv.round_id FROM round_commitment_tx_vw rctv WHERE rctv.txid = @txid)
    AND t.type = 'forfeit';


-- name: GetRoundConnectorTreeTxs :many
SELECT t.* FROM tx t
WHERE t.round_id IN (SELECT rctv.round_id FROM round_commitment_tx_vw rctv WHERE rctv.txid = @txid)
    AND t.type = 'connector';


-- name: GetSpendableVtxosWithPubKey :many
SELECT sqlc.embed(vtxo_virtual_tx_vw)FROM vtxo_virtual_tx_vw
WHERE pubkey = @pubkey AND spent = false AND swept = false;

-- name: SelectSweptRoundsConnectorAddress :many
SELECT round.connector_address FROM round
WHERE round.swept = true AND round.failed = false AND round.ended = true AND round.connector_address <> '';

-- name: SelectRoundIdsInRange :many
SELECT id FROM round WHERE starting_timestamp > @start_ts AND starting_timestamp < @end_ts;

-- name: SelectRoundIds :many
SELECT id FROM round;

-- name: UpsertVtxo :exec
INSERT INTO vtxo (txid, vout, pubkey, amount, commitment_txid, spent_by, spent, redeemed, swept, expire_at, created_at)
VALUES (@txid, @vout, @pubkey, @amount, @commitment_txid, @spent_by, @spent, @redeemed, @swept, @expire_at, @created_at) ON CONFLICT(txid, vout) DO UPDATE SET
    pubkey = EXCLUDED.pubkey,
    amount = EXCLUDED.amount,
    commitment_txid = EXCLUDED.commitment_txid,
    spent_by = EXCLUDED.spent_by,
    spent = EXCLUDED.spent,
    redeemed = EXCLUDED.redeemed,
    swept = EXCLUDED.swept,
    expire_at = EXCLUDED.expire_at,
    created_at = EXCLUDED.created_at;

-- name: InsertVtxoCommitmentTxid :exec
INSERT INTO vtxo_commitment_txid (vtxo_txid, vtxo_vout, commitment_txid)
VALUES (@vtxo_txid, @vtxo_vout, @commitment_txid);

-- name: SelectSweepableVtxos :many
SELECT sqlc.embed(vtxo_virtual_tx_vw) FROM vtxo_virtual_tx_vw
WHERE redeemed = false AND swept = false;

-- name: SelectNotRedeemedVtxos :many
SELECT sqlc.embed(vtxo_virtual_tx_vw) FROM vtxo_virtual_tx_vw
WHERE redeemed = false;

-- name: SelectNotRedeemedVtxosWithPubkey :many
SELECT sqlc.embed(vtxo_virtual_tx_vw) FROM vtxo_virtual_tx_vw
WHERE redeemed = false AND pubkey = @pubkey;

-- name: SelectVtxoByOutpoint :one
SELECT sqlc.embed(vtxo_virtual_tx_vw) FROM vtxo_virtual_tx_vw
WHERE txid = @txid AND vout = @vout;

-- name: SelectAllVtxos :many
SELECT sqlc.embed(vtxo_virtual_tx_vw) FROM vtxo_virtual_tx_vw;

-- name: SelectVtxosByRoundTxid :many
SELECT sqlc.embed(vtxo_virtual_tx_vw) FROM vtxo_virtual_tx_vw
WHERE commitment_txid = @commitment_txid;

-- name: MarkVtxoAsRedeemed :exec
UPDATE vtxo SET redeemed = true WHERE txid = @txid AND vout = @vout;

-- name: MarkVtxoAsSwept :exec
UPDATE vtxo SET swept = true WHERE txid = @txid AND vout = @vout;

-- name: MarkVtxoAsSpent :exec
UPDATE vtxo SET spent = true, spent_by = @spent_by WHERE txid = @txid AND vout = @vout;

-- name: UpdateVtxoExpireAt :exec
UPDATE vtxo SET expire_at = @expire_at WHERE txid = @txid AND vout = @vout;

-- name: InsertMarketHour :one
INSERT INTO market_hour (
    start_time,
    end_time,
    period,
    round_interval,
    updated_at
) VALUES (@start_time, @end_time, @period, @round_interval, @updated_at)
    RETURNING *;

-- name: UpsertMarketHour :exec
INSERT INTO market_hour (
    id, start_time, end_time, period, round_interval, updated_at
) VALUES (
             @id, @start_time, @end_time, @period, @round_interval, @updated_at
         )
    ON CONFLICT (id) DO UPDATE SET
    start_time = EXCLUDED.start_time,
    end_time = EXCLUDED.end_time,
    period = EXCLUDED.period,
    round_interval = EXCLUDED.round_interval,
    updated_at = EXCLUDED.updated_at;


-- name: GetLatestMarketHour :one
SELECT * FROM market_hour ORDER BY updated_at DESC LIMIT 1;

-- name: SelectTreeTxsWithRoundTxid :many
SELECT * FROM tx
WHERE round_id IN (SELECT rctv.round_id FROM round_commitment_tx_vw rctv WHERE rctv.txid = @txid) AND type = 'tree';

-- name: SelectVtxosWithPubkey :many
SELECT sqlc.embed(vtxo_virtual_tx_vw) FROM vtxo_virtual_tx_vw WHERE pubkey = @pubkey;

-- name: GetExistingRounds :many
SELECT * FROM round_commitment_tx_vw r
WHERE r.txid = ANY($1::varchar[]);

-- name: SelectLeafVtxosByRoundTxid :many
SELECT sqlc.embed(vtxo_virtual_tx_vw) FROM vtxo_virtual_tx_vw
WHERE commitment_txid = @commitment_txid AND (redeem_tx IS NULL or redeem_tx = '');

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
    txid, tx, commitment_txid, is_root_commitment_txid, virtual_txid
) VALUES (@txid, @tx, @commitment_txid, @is_root_commitment_txid, @virtual_txid)
    ON CONFLICT(txid) DO UPDATE SET
    tx = EXCLUDED.tx,
    commitment_txid = EXCLUDED.commitment_txid,
    is_root_commitment_txid = EXCLUDED.is_root_commitment_txid,
    virtual_txid = EXCLUDED.virtual_txid;

-- name: SelectVirtualTxWithTxId :many
SELECT  sqlc.embed(virtual_tx_checkpoint_tx_vw)
FROM virtual_tx_checkpoint_tx_vw WHERE txid = @txid;