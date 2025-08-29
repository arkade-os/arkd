-- name: UpsertRound :exec
INSERT INTO round (
    id, starting_timestamp, ending_timestamp, ended, failed, fail_reason,
    stage_code, connector_address, version, swept, vtxo_tree_expiration
) VALUES (
    @id, @starting_timestamp, @ending_timestamp, @ended, @failed, @fail_reason,
    @stage_code, @connector_address, @version, @swept, @vtxo_tree_expiration
)
ON CONFLICT(id) DO UPDATE SET
    starting_timestamp = EXCLUDED.starting_timestamp,
    ending_timestamp = EXCLUDED.ending_timestamp,
    ended = EXCLUDED.ended,
    failed = EXCLUDED.failed,
    fail_reason = EXCLUDED.fail_reason,
    stage_code = EXCLUDED.stage_code,
    connector_address = EXCLUDED.connector_address,
    version = EXCLUDED.version,
    swept = EXCLUDED.swept,
    vtxo_tree_expiration = EXCLUDED.vtxo_tree_expiration;

-- name: UpsertTx :exec
INSERT INTO tx (tx, round_id, type, position, txid, children)
VALUES (@tx, @round_id, @type, @position, @txid, @children)
ON CONFLICT(txid) DO UPDATE SET
    tx = EXCLUDED.tx,
    round_id = EXCLUDED.round_id,
    type = EXCLUDED.type,
    position = EXCLUDED.position,
    txid = EXCLUDED.txid,
    children = EXCLUDED.children;

-- name: UpsertIntent :exec
INSERT INTO intent (id, round_id, proof, message) VALUES (@id, @round_id, @proof, @message)
ON CONFLICT(id) DO UPDATE SET
    round_id = EXCLUDED.round_id,
    proof = EXCLUDED.proof,
    message = EXCLUDED.message;

-- name: UpsertReceiver :exec
INSERT INTO receiver (intent_id, pubkey, onchain_address, amount)
VALUES (@intent_id, @pubkey, @onchain_address, @amount)
ON CONFLICT(intent_id, pubkey, onchain_address) DO UPDATE SET
    amount = EXCLUDED.amount,
    pubkey = EXCLUDED.pubkey,
    onchain_address = EXCLUDED.onchain_address;

-- name: UpsertVtxo :exec
INSERT INTO vtxo (
    txid, vout, pubkey, amount, commitment_txid, settled_by, ark_txid,
    spent_by, spent, unrolled, swept, preconfirmed, expires_at, created_at
)
VALUES (
    @txid, @vout, @pubkey, @amount, @commitment_txid, @settled_by, @ark_txid,
    @spent_by, @spent, @unrolled, @swept, @preconfirmed, @expires_at, @created_at
) ON CONFLICT(txid, vout) DO UPDATE SET
    pubkey = EXCLUDED.pubkey,
    amount = EXCLUDED.amount,
    commitment_txid = EXCLUDED.commitment_txid,
    settled_by = EXCLUDED.settled_by,
    ark_txid = EXCLUDED.ark_txid,
    spent_by = EXCLUDED.spent_by,
    spent = EXCLUDED.spent,
    unrolled = EXCLUDED.unrolled,
    swept = EXCLUDED.swept,
    preconfirmed = EXCLUDED.preconfirmed,
    expires_at = EXCLUDED.expires_at,
    created_at = EXCLUDED.created_at;

-- name: InsertVtxoCommitmentTxid :exec
INSERT INTO vtxo_commitment_txid (vtxo_txid, vtxo_vout, commitment_txid)
VALUES (@vtxo_txid, @vtxo_vout, @commitment_txid);

-- name: UpsertOffchainTx :exec
INSERT INTO offchain_tx (txid, tx, starting_timestamp, ending_timestamp, expiry_timestamp, fail_reason, stage_code)
VALUES (@txid, @tx, @starting_timestamp, @ending_timestamp, @expiry_timestamp, @fail_reason, @stage_code)
ON CONFLICT(txid) DO UPDATE SET
    tx = EXCLUDED.tx,
    starting_timestamp = EXCLUDED.starting_timestamp,
    ending_timestamp = EXCLUDED.ending_timestamp,
    expiry_timestamp = EXCLUDED.expiry_timestamp,
    fail_reason = EXCLUDED.fail_reason,
    stage_code = EXCLUDED.stage_code;

-- name: UpsertCheckpointTx :exec
INSERT INTO checkpoint_tx (txid, tx, commitment_txid, is_root_commitment_txid, offchain_txid)
VALUES (@txid, @tx, @commitment_txid, @is_root_commitment_txid, @offchain_txid)
ON CONFLICT(txid) DO UPDATE SET
    tx = EXCLUDED.tx,
    commitment_txid = EXCLUDED.commitment_txid,
    is_root_commitment_txid = EXCLUDED.is_root_commitment_txid,
    offchain_txid = EXCLUDED.offchain_txid;

-- name: UpsertMarketHour :exec
INSERT INTO market_hour (id, start_time, end_time, period, round_interval, updated_at)
VALUES (@id, @start_time, @end_time, @period, @round_interval, @updated_at)
ON CONFLICT (id) DO UPDATE SET
    start_time = EXCLUDED.start_time,
    end_time = EXCLUDED.end_time,
    period = EXCLUDED.period,
    round_interval = EXCLUDED.round_interval,
    updated_at = EXCLUDED.updated_at;

-- name: UpdateVtxoIntentId :exec
UPDATE vtxo SET intent_id = @intent_id WHERE txid = @txid AND vout = @vout;

-- name: UpdateVtxoExpiration :exec
UPDATE vtxo SET expires_at = @expires_at WHERE txid = @txid AND vout = @vout;

-- name: UpdateVtxoUnrolled :exec
UPDATE vtxo SET unrolled = true WHERE txid = @txid AND vout = @vout;

-- name: UpdateVtxoSwept :exec
UPDATE vtxo SET swept = true WHERE txid = @txid AND vout = @vout;

-- name: UpdateVtxoSettled :exec
UPDATE vtxo SET spent = true, spent_by = @spent_by, settled_by = @settled_by
WHERE txid = @txid AND vout = @vout;

-- name: UpdateVtxoSpent :exec
UPDATE vtxo SET spent = true, spent_by = @spent_by, ark_txid = @ark_txid
WHERE txid = @txid AND vout = @vout;

-- name: SelectRoundWithId :many
SELECT sqlc.embed(round),
    sqlc.embed(round_intents_vw),
    sqlc.embed(round_txs_vw),
    sqlc.embed(intent_with_receivers_vw),
    sqlc.embed(intent_with_inputs_vw)
FROM round
LEFT OUTER JOIN round_intents_vw ON round.id=round_intents_vw.round_id
LEFT OUTER JOIN round_txs_vw ON round.id=round_txs_vw.round_id
LEFT OUTER JOIN intent_with_receivers_vw ON round_intents_vw.id=intent_with_receivers_vw.intent_id
LEFT OUTER JOIN intent_with_inputs_vw ON round_intents_vw.id=intent_with_inputs_vw.intent_id
WHERE round.id = @id;

-- name: SelectRoundWithTxid :many
SELECT sqlc.embed(round),
    sqlc.embed(round_intents_vw),
    sqlc.embed(round_txs_vw),
    sqlc.embed(intent_with_receivers_vw),
    sqlc.embed(intent_with_inputs_vw)
FROM round
LEFT OUTER JOIN round_intents_vw ON round.id=round_intents_vw.round_id
LEFT OUTER JOIN round_txs_vw ON round.id=round_txs_vw.round_id
LEFT OUTER JOIN intent_with_receivers_vw ON round_intents_vw.id=intent_with_receivers_vw.intent_id
LEFT OUTER JOIN intent_with_inputs_vw ON round_intents_vw.id=intent_with_inputs_vw.intent_id
WHERE round.id = (
    SELECT tx.round_id FROM tx WHERE tx.txid = @txid AND type = 'commitment'
);

-- name: SelectSweepableRounds :many
SELECT txid FROM round_with_commitment_tx_vw r WHERE r.swept = false AND r.ended = true AND r.failed = false;

-- name: SelectRoundIdsInTimeRange :many
SELECT id FROM round WHERE starting_timestamp > @start_ts AND starting_timestamp < @end_ts;

-- name: SelectAllRoundIds :many
SELECT id FROM round;

-- name: SelectRoundsWithTxids :many
SELECT txid FROM tx WHERE type = 'commitment' AND tx.txid IN (sqlc.slice('txids'));

-- name: SelectRoundConnectors :many
SELECT t.* FROM tx t WHERE t.round_id = (
    SELECT tx.round_id FROM tx WHERE tx.txid = @txid AND type = 'commitment'
) AND t.type = 'connector';

-- name: SelectRoundVtxoTree :many
SELECT * FROM tx WHERE round_id = (
    SELECT tx.round_id FROM tx WHERE tx.txid = @txid AND type = 'commitment'
) AND type = 'tree';

-- name: SelectRoundVtxoTreeLeaves :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE commitment_txid = @commitment_txid AND preconfirmed = false;

-- name: SelectRoundForfeitTxs :many
SELECT t.* FROM tx t WHERE t.round_id IN (
    SELECT tx.round_id FROM tx WHERE tx.txid = @txid AND type = 'commitment'
) AND t.type = 'forfeit';

-- name: SelectRoundStats :one
SELECT
    r.swept,
    r.starting_timestamp,
    r.ending_timestamp,
    (
        SELECT COALESCE(SUM(amount), 0) FROM (
            SELECT DISTINCT v2.* FROM vtxo v2 JOIN intent i2 ON i2.id = v2.intent_id WHERE i2.round_id = r.id
        ) as intent_with_inputs_amount
    ) AS total_forfeit_amount,
    (
        SELECT COALESCE(COUNT(v3.txid), 0) FROM vtxo v3 JOIN intent i3 ON i3.id = v3.intent_id WHERE i3.round_id = r.id
    ) AS total_input_vtxos,
    (
        SELECT COALESCE(SUM(amount), 0) FROM (
            SELECT DISTINCT rr.* FROM receiver rr
            JOIN intent i4 ON i4.id = rr.intent_id
            WHERE i4.round_id = r.id AND COALESCE(rr.onchain_address, '') = ''
        ) AS intent_outputs_amount
    ) AS total_batch_amount,
    (
        SELECT COUNT(*) FROM tx t WHERE t.round_id = r.id AND t.type = 'tree' AND TRIM(COALESCE(t.children, '')) = ''
    ) AS total_output_vtxos,
    (
        SELECT MAX(v.expires_at) FROM vtxo_vw v WHERE v.commitment_txid = r.txid
    ) AS expires_at
FROM round_with_commitment_tx_vw r
WHERE r.txid = @txid;

-- name: SelectSweptRoundsConnectorAddress :many
SELECT round.connector_address FROM round
WHERE round.swept = true AND round.failed = false AND round.ended = true AND round.connector_address <> '';

-- name: SelectTxs :many
SELECT tx.txid, tx.tx AS data FROM tx WHERE tx.txid IN (sqlc.slice('ids1'))
UNION
SELECT offchain_tx.txid, offchain_tx.tx AS data FROM offchain_tx WHERE offchain_tx.txid IN (sqlc.slice('ids2'))
UNION
SELECT checkpoint_tx.txid, checkpoint_tx.tx AS data FROM checkpoint_tx WHERE checkpoint_tx.txid IN (sqlc.slice('ids3'));

-- name: SelectSweepableVtxos :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE unrolled = false AND swept = false;

-- name: SelectNotUnrolledVtxos :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE unrolled = false;

-- name: SelectNotUnrolledVtxosWithPubkey :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE unrolled = false AND pubkey = @pubkey;

-- name: SelectVtxo :one
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE txid = @txid AND vout = @vout;

-- name: SelectAllVtxos :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw;

-- name: SelectVtxosWithCommitmentTxid :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE commitment_txid = @commitment_txid;

-- name: SelectVtxosWithPubkeys :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE pubkey IN (sqlc.slice('pubkey'));

-- name: SelectOffchainTx :many
SELECT  sqlc.embed(offchain_tx_vw) FROM offchain_tx_vw WHERE txid = @txid;

-- name: SelectLatestMarketHour :one
SELECT * FROM market_hour ORDER BY updated_at DESC LIMIT 1;

-- name: SelectSweepableUnrolledVtxos :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE spent = true AND unrolled = true AND swept = false AND (COALESCE(settled_by, '') = '');