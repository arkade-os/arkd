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
INSERT INTO intent (id, round_id, proof, message, txid) VALUES (@id, @round_id, @proof, @message, @txid)
ON CONFLICT(id) DO UPDATE SET
    round_id = EXCLUDED.round_id,
    proof = EXCLUDED.proof,
    message = EXCLUDED.message,
    txid = EXCLUDED.txid;

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
    spent_by, spent, unrolled, preconfirmed, expires_at, created_at, updated_at, depth, markers
)
VALUES (
    @txid, @vout, @pubkey, @amount, @commitment_txid, @settled_by, @ark_txid,
    @spent_by, @spent, @unrolled, @preconfirmed, @expires_at, @created_at, (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT, @depth, @markers
) ON CONFLICT(txid, vout) DO UPDATE SET
    pubkey = EXCLUDED.pubkey,
    amount = EXCLUDED.amount,
    commitment_txid = EXCLUDED.commitment_txid,
    settled_by = EXCLUDED.settled_by,
    ark_txid = EXCLUDED.ark_txid,
    spent_by = EXCLUDED.spent_by,
    spent = EXCLUDED.spent,
    unrolled = EXCLUDED.unrolled,
    preconfirmed = EXCLUDED.preconfirmed,
    expires_at = EXCLUDED.expires_at,
    created_at = EXCLUDED.created_at,
    updated_at = (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
    depth = EXCLUDED.depth,
    markers = EXCLUDED.markers;

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
UPDATE vtxo SET unrolled = true, updated_at = (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT WHERE txid = @txid AND vout = @vout;

-- name: UpdateVtxoSettled :exec
UPDATE vtxo SET spent = true, spent_by = @spent_by, settled_by = @settled_by, updated_at = (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT
WHERE txid = @txid AND vout = @vout;

-- name: UpdateVtxoSpent :exec
UPDATE vtxo SET spent = true, spent_by = @spent_by, ark_txid = @ark_txid, updated_at = (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT
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

-- name: SelectVtxo :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE txid = @txid AND vout = @vout;

-- name: SelectAllVtxos :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw;

-- name: SelectVtxosWithPubkeys :many
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw
WHERE vtxo_vw.pubkey = ANY($1::varchar[])
    AND vtxo_vw.updated_at >= @after::bigint
    AND (@before::bigint = 0 OR vtxo_vw.updated_at <= @before::bigint);

-- name: SelectExpiringLiquidityAmount :one
SELECT COALESCE(SUM(v.amount), 0)::bigint AS amount
FROM vtxo v
WHERE NOT EXISTS (
        SELECT 1 FROM swept_marker sm
        WHERE v.markers @> jsonb_build_array(sm.marker_id)
    )
  AND v.spent = false
  AND v.unrolled = false
  AND v.expires_at > @after
  AND (@before <= 0 OR v.expires_at < @before);

-- name: SelectRecoverableLiquidityAmount :one
SELECT COALESCE(SUM(v.amount), 0)::bigint AS amount
FROM vtxo v
WHERE EXISTS (
        SELECT 1 FROM swept_marker sm
        WHERE v.markers @> jsonb_build_array(sm.marker_id)
    )
  AND v.spent = false;

-- name: SelectOffchainTx :many
SELECT sqlc.embed(offchain_tx_vw) FROM offchain_tx_vw WHERE txid = @txid AND COALESCE(fail_reason, '') = '';

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
    )
    AND v.updated_at >= @after::bigint
    AND (@before::bigint = 0 OR v.updated_at <= @before::bigint);

-- name: SelectPendingSpentVtxo :many
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


-- name: SelectIntentByTxid :one
SELECT id, txid, proof, message FROM intent
WHERE txid = @txid;

-- Marker queries

-- name: UpsertMarker :exec
INSERT INTO marker (id, depth, parent_markers)
VALUES (@id, @depth, @parent_markers)
ON CONFLICT(id) DO UPDATE SET
    depth = EXCLUDED.depth,
    parent_markers = EXCLUDED.parent_markers;

-- name: SelectMarker :one
SELECT * FROM marker WHERE id = @id;

-- name: SelectMarkersByDepth :many
SELECT * FROM marker WHERE depth = @depth;

-- name: SelectMarkersByDepthRange :many
SELECT * FROM marker WHERE depth >= @min_depth AND depth <= @max_depth ORDER BY depth;

-- name: SelectMarkersByIds :many
SELECT * FROM marker WHERE id = ANY(@ids::text[]);

-- name: InsertSweptMarker :exec
INSERT INTO swept_marker (marker_id, swept_at)
VALUES (@marker_id, @swept_at)
ON CONFLICT(marker_id) DO NOTHING;

-- name: BulkInsertSweptMarkers :exec
INSERT INTO swept_marker (marker_id, swept_at)
SELECT unnest(@marker_ids::text[]), @swept_at
ON CONFLICT(marker_id) DO NOTHING;

-- name: SelectSweptMarker :one
SELECT * FROM swept_marker WHERE marker_id = @marker_id;

-- name: SelectSweptMarkersByIds :many
SELECT * FROM swept_marker WHERE marker_id = ANY(@marker_ids::text[]);

-- name: IsMarkerSwept :one
SELECT EXISTS(SELECT 1 FROM swept_marker WHERE marker_id = @marker_id) AS is_swept;

-- name: GetDescendantMarkerIds :many
-- Recursively get a marker and all its descendants (markers whose parent_markers contain it)
WITH RECURSIVE descendant_markers(id) AS (
    -- Base case: the marker being swept
    SELECT marker.id FROM marker WHERE marker.id = @root_marker_id
    UNION ALL
    -- Recursive case: find markers whose parent_markers jsonb array contains any descendant
    SELECT m.id FROM marker m
    INNER JOIN descendant_markers dm ON (
        m.parent_markers @> jsonb_build_array(dm.id)
    )
)
SELECT descendant_markers.id AS marker_id FROM descendant_markers
WHERE descendant_markers.id NOT IN (SELECT sm.marker_id FROM swept_marker sm);

-- name: UpdateVtxoMarkers :exec
UPDATE vtxo SET markers = @markers::jsonb WHERE txid = @txid AND vout = @vout;

-- name: SelectVtxosByMarkerId :many
-- Find VTXOs whose markers JSONB array contains the given marker_id
SELECT sqlc.embed(vtxo_vw) FROM vtxo_vw WHERE markers @> jsonb_build_array(@marker_id::TEXT);

-- name: CountUnsweptVtxosByMarkerId :one
-- Count VTXOs whose markers JSONB array contains the given marker_id and are not swept
SELECT COUNT(*) FROM vtxo_vw WHERE markers @> jsonb_build_array(@marker_id::TEXT) AND swept = false;

-- Chain traversal queries for GetVtxoChain optimization

-- name: SelectVtxosByDepthRange :many
-- Get all VTXOs within a depth range, useful for filling gaps between markers
SELECT * FROM vtxo_vw
WHERE depth >= @min_depth AND depth <= @max_depth
ORDER BY depth DESC;

-- name: SelectVtxosByArkTxid :many
-- Get all VTXOs created by a specific ark tx (offchain tx)
SELECT * FROM vtxo_vw WHERE txid = @ark_txid;

-- name: SelectVtxoChainByMarker :many
-- Get VTXOs whose markers JSONB array contains any of the given marker IDs
SELECT * FROM vtxo_vw
WHERE markers ?| @marker_ids::TEXT[]
ORDER BY depth DESC;

-- name: InsertAsset :exec
INSERT INTO asset (id, is_immutable, metadata_hash, metadata, control_asset_id)
VALUES (@id, @is_immutable, @metadata_hash, @metadata, @control_asset_id);

-- name: InsertVtxoAssetProjection :exec
INSERT INTO asset_projection (asset_id, txid, vout, amount)
VALUES (@asset_id, @txid, @vout, @amount);

-- name: SelectAssetsByIds :many
SELECT * FROM asset WHERE asset.id = ANY($1::varchar[]);

-- name: SelectAssetSupply :one
SELECT (COALESCE(SUM(ap.amount), 0))::TEXT AS supply
FROM asset_projection ap
INNER JOIN vtxo v ON v.txid = ap.txid AND v.vout = ap.vout
WHERE ap.asset_id = $1 AND v.spent = false;

-- name: SelectControlAssetByID :one
SELECT control_asset_id FROM asset WHERE id = $1;

-- name: SelectAssetExists :one
SELECT 1 FROM asset WHERE id = $1 LIMIT 1;
