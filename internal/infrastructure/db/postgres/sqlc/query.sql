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

-- name: UpsertScheduledSession :exec
INSERT INTO scheduled_session (id, start_time, end_time, period, duration, round_min_participants, round_max_participants, updated_at)
VALUES (@id, @start_time, @end_time, @period, @duration, @round_min_participants, @round_max_participants, @updated_at)
ON CONFLICT (id) DO UPDATE SET
    start_time = EXCLUDED.start_time,
    end_time = EXCLUDED.end_time,
    period = EXCLUDED.period,
    duration = EXCLUDED.duration,
    round_min_participants = EXCLUDED.round_min_participants,
    round_max_participants = EXCLUDED.round_max_participants,
    updated_at = EXCLUDED.updated_at;

-- name: ClearScheduledSession :exec
DELETE FROM scheduled_session;

-- name: UpdateVtxoIntentId :exec
UPDATE vtxo SET intent_id = @intent_id WHERE txid = @txid AND vout = @vout;

-- name: UpdateVtxoExpiration :exec
UPDATE vtxo SET expires_at = @expires_at WHERE txid = @txid AND vout = @vout;

-- name: UpdateVtxoUnrolled :exec
UPDATE vtxo SET unrolled = true WHERE txid = @txid AND vout = @vout;

-- name: UpdateVtxoSweptIfNotSwept :execrows
UPDATE vtxo SET swept = true WHERE txid = @txid AND vout = @vout AND swept = false;

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
SELECT txid FROM round_with_commitment_tx_vw r 
WHERE r.swept = false AND r.ended = true AND r.failed = false
AND EXISTS (
    SELECT 1 FROM tx tree_tx 
    WHERE tree_tx.round_id = r.id AND tree_tx.type = 'tree'
);

-- name: SelectRoundIdsInTimeRange :many
SELECT id FROM round WHERE starting_timestamp > @start_ts AND starting_timestamp < @end_ts;

-- name: SelectAllRoundIds :many
SELECT id FROM round;

-- name: SelectRoundIdsWithFilters :many
SELECT id FROM round 
WHERE (@with_failed::boolean = true OR failed = false)
  AND (@with_completed::boolean = true OR ended = false);

-- name: SelectRoundIdsInTimeRangeWithFilters :many
SELECT id FROM round 
WHERE starting_timestamp > @start_ts 
  AND starting_timestamp < @end_ts
  AND (@with_failed::boolean = true OR failed = false)
  AND (@with_completed::boolean = true OR ended = false);

-- name: SelectRoundsWithTxids :many
SELECT txid FROM tx WHERE type = 'commitment' AND tx.txid = ANY($1::varchar[]);

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
        SELECT COALESCE(SUM(ii.amount), 0)::bigint FROM intent_with_inputs_vw ii WHERE ii.round_id = r.id
    ) AS total_forfeit_amount,
    (
        SELECT COALESCE(COUNT(ii.txid), 0)::bigint FROM intent_with_inputs_vw ii WHERE ii.round_id = r.id
    ) AS total_input_vtxos,
    (
        SELECT COALESCE(SUM(ir.amount), 0)::bigint FROM intent_with_receivers_vw ir
        WHERE ir.round_id = r.id AND COALESCE(ir.onchain_address, '') = ''
    ) AS total_batch_amount,
    (
        SELECT COUNT(*) FROM intent_with_receivers_vw ir WHERE ir.round_id = r.id AND COALESCE(ir.onchain_address, '') = ''
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
SELECT tx.txid, tx.tx AS data FROM tx WHERE tx.txid = ANY($1::varchar[])
UNION
SELECT offchain_tx.txid, offchain_tx.tx AS data FROM offchain_tx WHERE offchain_tx.txid = ANY($1::varchar[])
UNION
SELECT checkpoint_tx.txid, checkpoint_tx.tx AS data FROM checkpoint_tx WHERE checkpoint_tx.txid = ANY($1::varchar[]);

-- name: SelectNotUnrolledVtxos :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE unrolled = false;

-- name: SelectNotUnrolledVtxosWithPubkey :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE unrolled = false AND pubkey = @pubkey;

-- name: SelectVtxo :one
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE txid = @txid AND vout = @vout;

-- name: SelectAllVtxos :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw;

-- name: SelectVtxosWithPubkeys :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE pubkey = ANY($1::varchar[]);

-- name: SelectExpiringLiquidityAmount :one
SELECT COALESCE(SUM(amount), 0)::bigint AS amount
FROM vtxo
WHERE swept = false
  AND spent = false
  AND unrolled = false
  AND expires_at > @after
  AND (@before <= 0 OR expires_at < @before);

-- name: SelectRecoverableLiquidityAmount :one
SELECT COALESCE(SUM(amount), 0)::bigint AS amount
FROM vtxo
WHERE swept = true
  AND spent = false;

-- name: SelectOffchainTx :many
SELECT  sqlc.embed(offchain_tx_vw) FROM offchain_tx_vw WHERE txid = @txid;

-- name: SelectLatestScheduledSession :one
SELECT * FROM scheduled_session ORDER BY updated_at DESC LIMIT 1;

-- name: SelectVtxoPubKeysByCommitmentTxid :many
SELECT DISTINCT v.pubkey 
FROM vtxo_vw v
WHERE v.amount >= @min_amount
  AND (v.commitment_txid = @commitment_txid
    OR (',' || COALESCE(v.commitments::text, '') || ',') LIKE '%,' || @commitment_txid || ',%');

-- name: SelectSweepableVtxoOutpointsByCommitmentTxid :many
SELECT DISTINCT v.txid AS vtxo_txid, v.vout AS vtxo_vout
FROM vtxo_vw v
WHERE v.swept = false
  AND (v.commitment_txid = @commitment_txid
    OR (',' || COALESCE(v.commitments::text, '') || ',') LIKE '%,' || @commitment_txid || ',%');

-- name: SelectVtxosOutpointsByArkTxidRecursive :many
WITH RECURSIVE descendants_chain AS (
    -- seed
    SELECT v.txid, v.vout, v.preconfirmed, v.ark_txid, v.spent_by,
           0 AS depth,
           ARRAY[(v.txid||':'||v.vout)]::text[] AS visited
    FROM vtxo v
    WHERE v.txid = @txid

    UNION ALL

    -- children: next vtxo(s) are those whose txid == current.ark_txid
    SELECT c.txid, c.vout, c.preconfirmed, c.ark_txid, c.spent_by,
           w.depth + 1,
           w.visited || (c.txid||':'||c.vout)
    FROM descendants_chain w
             JOIN vtxo c
                  ON c.txid = w.ark_txid
    WHERE w.ark_txid IS NOT NULL
      AND (c.txid||':'||c.vout) <> ALL (w.visited)   -- cycle/visited guard
),
-- keep one row per node at its MIN depth (layers)
nodes AS (
   SELECT DISTINCT ON (txid, vout)
       txid, vout, preconfirmed, depth
   FROM descendants_chain
   ORDER BY txid, vout, depth
)
SELECT txid, vout
FROM nodes
ORDER BY depth, txid, vout;

-- name: SelectSweepableUnrolledVtxos :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE spent = true AND unrolled = true AND swept = false AND COALESCE(settled_by, '') = '';

-- name: SelectPendingSpentVtxosWithPubkeys :many
SELECT v.*
FROM vtxo_vw v
WHERE v.spent = TRUE AND v.unrolled = FALSE and COALESCE(v.settled_by, '') = ''
    AND v.pubkey = ANY($1::varchar[])
    AND v.ark_txid IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM vtxo AS o WHERE o.txid = v.ark_txid
    );

-- name: SelectPendingSpentVtxo :one
SELECT v.*
FROM vtxo_vw v
WHERE v.txid = @txid AND v.vout = @vout
    AND v.spent = TRUE AND v.unrolled = FALSE and COALESCE(v.settled_by, '') = ''
    AND v.ark_txid IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM vtxo AS o WHERE o.txid = v.ark_txid
    );

-- name: UpsertConviction :exec
INSERT INTO conviction (
    id, type, created_at, expires_at, crime_type, crime_round_id, crime_reason, pardoned, script
) VALUES (
    @id, @type, @created_at, @expires_at, @crime_type, @crime_round_id, @crime_reason, @pardoned, @script
)
ON CONFLICT(id) DO UPDATE SET
    pardoned = EXCLUDED.pardoned;

-- name: SelectConviction :one
SELECT * FROM conviction WHERE id = @id;

-- name: SelectActiveScriptConvictions :many
SELECT * FROM conviction 
WHERE script = @script 
AND pardoned = false 
AND (expires_at IS NULL OR expires_at > @expires_at)
ORDER BY created_at ASC;

-- name: UpdateConvictionPardoned :exec
UPDATE conviction SET pardoned = true WHERE id = @id;

-- name: SelectConvictionsInTimeRange :many
SELECT * FROM conviction 
WHERE created_at >= @from_time AND created_at <= @to_time
ORDER BY created_at ASC;

-- name: SelectConvictionsByRoundID :many
SELECT * FROM conviction 
WHERE crime_round_id = @round_id
ORDER BY created_at ASC;

-- name: CreateAssetAnchor :exec
INSERT INTO asset_anchor (anchor_txid, anchor_vout)
VALUES (@anchor_txid, @anchor_vout);

-- name: ListAssetAnchorsByAssetID :many
SELECT aa.anchor_txid, aa.anchor_vout
FROM asset_anchor aa
JOIN asset a ON aa.anchor_txid = a.anchor_id
WHERE a.asset_id = @asset_id
ORDER BY aa.anchor_txid;

-- name: GetAssetAnchor :one
SELECT anchor_txid, anchor_vout
FROM asset_anchor
WHERE anchor_txid = @anchor_txid;

-- name: DeleteAssetAnchor :exec
DELETE FROM asset_anchor
WHERE anchor_txid = @anchor_txid;

-- name: UpsertAssetMetadata :exec
INSERT INTO asset_metadata (asset_id, meta_key, meta_value)
VALUES (@asset_id, @meta_key, @meta_value)
ON CONFLICT (asset_id, meta_key)
DO UPDATE SET meta_value = EXCLUDED.meta_value;

-- name: GetAssetMetadata :one
SELECT asset_id, meta_key, meta_value
FROM asset_metadata
WHERE asset_id = @asset_id AND meta_key = @meta_key;

-- name: ListAssetMetadata :many
SELECT asset_id, meta_key, meta_value
FROM asset_metadata
WHERE asset_id = @asset_id
ORDER BY meta_key;

-- name: AddAsset :exec
INSERT INTO asset (anchor_id, asset_id, vout, amount)
VALUES (@anchor_id, @asset_id, @vout, @amount)
ON CONFLICT (anchor_id, vout)
DO UPDATE SET amount = EXCLUDED.amount;

-- name: GetAsset :one
SELECT anchor_id, asset_id, vout, amount
FROM asset
WHERE anchor_id = @anchor_id AND vout = @vout;

-- name: DeleteAsset :exec
DELETE FROM asset
WHERE anchor_id = @anchor_id AND vout = @vout;

-- name: ListAsset :many
SELECT anchor_id, asset_id, vout, amount
FROM asset
WHERE anchor_id = @anchor_id
ORDER BY vout;

-- name: GetAssetGroup :one
SELECT id, quantity, immutable, control_id
FROM asset_group
WHERE id = @id;

-- name: ListAssetGroup :many
SELECT id, quantity, immutable, control_id
FROM asset_group
ORDER BY id;

-- name: AddToAssetQuantity :exec
UPDATE asset_group
SET quantity = quantity + @quantity
WHERE id = @id;

-- name: SubtractFromAssetQuantity :exec
UPDATE asset_group
SET quantity = quantity - @quantity
WHERE id = @id AND quantity >= @quantity;

-- name: CreateAsset :exec
INSERT INTO asset_group (id, quantity, immutable, control_id)
VALUES (@id, @quantity, @immutable, @control_id);

-- name: CreateTeleportAsset :exec
INSERT INTO teleport_asset (script, intent_id, asset_id, group_index, amount, is_claimed)
VALUES (@script, @intent_id, @asset_id, @group_index, @amount, @is_claimed);

-- name: GetTeleportAsset :one
SELECT script, intent_id, asset_id, group_index, amount, is_claimed
FROM teleport_asset
WHERE script = @script AND intent_id = @intent_id AND asset_id = @asset_id AND group_index = @group_index;

-- name: UpdateTeleportAsset :exec
UPDATE teleport_asset
SET is_claimed = @is_claimed
WHERE script = @script AND intent_id = @intent_id AND asset_id = @asset_id AND group_index = @group_index;
-- name: SelectLatestIntentFees :one
SELECT * FROM intent_fees ORDER BY id DESC LIMIT 1;

-- name: AddIntentFees :exec
INSERT INTO intent_fees (
  offchain_input_fee_program,
  onchain_input_fee_program,
  offchain_output_fee_program,
  onchain_output_fee_program
)
SELECT
    -- if all fee programs are empty, set them all to empty, else use provided, but if provided is empty fetch and use latest for that fee program.
    -- if no rows exist in intent_fees, and a specific fee program is passed in as empty, default to empty string. 
  CASE 
    WHEN (@offchain_input_fee_program = '' AND @onchain_input_fee_program = '' AND @offchain_output_fee_program = '' AND @onchain_output_fee_program = '') THEN ''
    WHEN @offchain_input_fee_program <> '' THEN @offchain_input_fee_program
    ELSE COALESCE((SELECT offchain_input_fee_program FROM intent_fees ORDER BY created_at DESC LIMIT 1), '')
  END,
  CASE
    WHEN (@offchain_input_fee_program = '' AND @onchain_input_fee_program = '' AND @offchain_output_fee_program = '' AND @onchain_output_fee_program = '') THEN ''
    WHEN @onchain_input_fee_program <> '' THEN @onchain_input_fee_program
    ELSE COALESCE((SELECT onchain_input_fee_program FROM intent_fees ORDER BY created_at DESC LIMIT 1), '')
  END,
  CASE
    WHEN (@offchain_input_fee_program = '' AND @onchain_input_fee_program = '' AND @offchain_output_fee_program = '' AND @onchain_output_fee_program = '') THEN ''
    WHEN @offchain_output_fee_program <> '' THEN @offchain_output_fee_program
    ELSE COALESCE((SELECT offchain_output_fee_program FROM intent_fees ORDER BY created_at DESC LIMIT 1), '')
  END,
  CASE
    WHEN (@offchain_input_fee_program = '' AND @onchain_input_fee_program = '' AND @offchain_output_fee_program = '' AND @onchain_output_fee_program = '') THEN ''
    WHEN @onchain_output_fee_program <> '' THEN @onchain_output_fee_program
    ELSE COALESCE((SELECT onchain_output_fee_program FROM intent_fees ORDER BY created_at DESC LIMIT 1), '')
  END;

-- name: ClearIntentFees :exec
INSERT INTO intent_fees (
  offchain_input_fee_program,
  onchain_input_fee_program,
  offchain_output_fee_program,
  onchain_output_fee_program
)
VALUES ('', '', '', '');


