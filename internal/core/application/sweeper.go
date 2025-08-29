package application

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	log "github.com/sirupsen/logrus"
)

type sweeperTask struct {
	execute func() error
	id      string
	at      int64
}

// sweeper is an unexported service running while the main application service is started
// it is responsible for sweeping batch outputs that reached the expiration date.
// it also handles delaying the sweep events in case some parts of the tree are broadcasted
// when a round is finalized, the main application service schedules a sweep event on the newly created vtxo tree
type sweeper struct {
	wallet      ports.WalletService
	repoManager ports.RepoManager
	builder     ports.TxBuilder
	scheduler   ports.SchedulerService

	noteUriPrefix string

	// cache of scheduled tasks, avoid scheduling the same sweep event multiple times
	locker *sync.Mutex
	// TODO move the scheduled task map to LiveStore port
	scheduledTasks map[string]struct{}
}

func newSweeper(
	wallet ports.WalletService, repoManager ports.RepoManager, builder ports.TxBuilder,
	scheduler ports.SchedulerService, noteUriPrefix string,
) *sweeper {
	return &sweeper{
		wallet, repoManager, builder, scheduler,
		noteUriPrefix, &sync.Mutex{}, make(map[string]struct{}),
	}
}

func (s *sweeper) start() error {
	s.scheduler.Start()

	ctx := context.Background()

	sweepableBatches, err := s.repoManager.Rounds().GetSweepableRounds(ctx)
	if err != nil {
		return err
	}

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()

		if len(sweepableBatches) > 0 {
			log.Infof("sweeper: restoring %d sweepable batches", len(sweepableBatches))

			progress := 0.0
			count := 0
			for _, txid := range sweepableBatches {
				flatVtxoTree, err := s.repoManager.Rounds().GetRoundVtxoTree(ctx, txid)
				if err != nil {
					log.WithError(err).Error("error while getting round vtxo tree")
					continue
				}

				if len(flatVtxoTree) <= 0 {
					continue
				}

				vtxoTree, err := tree.NewTxTree(flatVtxoTree)
				if err != nil {
					log.WithError(err).Error("error while creating vtxo tree")
					continue
				}

				task := s.createBatchSweepTask(txid, vtxoTree)
				if err := task(); err != nil {
					log.WithError(err).Error("error while executing batch sweep task")
					continue
				}

				newProgress := (1.0 / float64(len(sweepableBatches))) + progress
				if int(newProgress*100) > int(progress*100) {
					progress = newProgress
					log.Infof("sweeper: restoring... %d%%", int(progress*100))
				}
				count++
			}

			log.Infof("sweeper: scheduled sweeping for %d batches", count)
		}
	}()

	sweepableUnrolledVtxos, err := s.repoManager.Vtxos().
		GetAllSweepableUnrolledVtxos(ctx)
	if err != nil {
		return err
	}

	network, err := s.wallet.GetNetwork(ctx)
	if err != nil {
		return err
	}

	go func() {
		defer wg.Done()

		for _, vtxo := range sweepableUnrolledVtxos {
			checkpointTxid := vtxo.SpentBy

			txs, err := s.repoManager.Rounds().
				GetTxsWithTxids(ctx, []string{checkpointTxid})
			if err != nil {
				log.WithError(err).Error("error while getting checkpoint tx")
				continue
			}

			if len(txs) <= 0 {
				log.Errorf("checkpoint tx %s not found", checkpointTxid)
				continue
			}

			ptx, err := psbt.NewFromRawBytes(strings.NewReader(txs[0]), true)
			if err != nil {
				log.WithError(err).Error("error while parsing checkpoint tx")
				continue
			}

			confirmed, blockHeight, blockTime, err := s.wallet.IsTransactionConfirmed(
				ctx,
				checkpointTxid,
			)
			if err != nil {
				log.WithError(err).Error("error while checking if vtxo tx is confirmed")
				continue
			}

			if confirmed {
				if err := s.scheduleCheckpointSweep(vtxo.Outpoint, ptx, blockHeight, blockTime); err != nil {
					log.WithError(err).Error("error while scheduling checkpoint sweep")
				}
				continue
			}

			// asyncronously wait for the tx to be confirmed
			go func() {
				blockHeight, blockTime := waitForConfirmation(
					ctx,
					checkpointTxid,
					s.wallet,
					*network,
				)

				if err := s.scheduleCheckpointSweep(vtxo.Outpoint, ptx, blockHeight, blockTime); err != nil {
					log.Errorf("failed to schedule checkpoint sweep: %s", err)
				}
			}()
		}
	}()

	wg.Wait()

	return nil
}

func (s *sweeper) stop() {
	s.scheduler.Stop()
}

// removeTask update the cached map of scheduled tasks
func (s *sweeper) removeTask(id string) {
	s.locker.Lock()
	defer s.locker.Unlock()
	delete(s.scheduledTasks, id)
}

func (s *sweeper) scheduleCheckpointSweep(
	vtxo domain.Outpoint,
	ptx *psbt.Packet,
	blockHeight int64,
	blockTime int64,
) error {
	txid := ptx.UnsignedTx.TxID()

	if len(ptx.Outputs) <= 0 {
		return fmt.Errorf("no outputs found in checkpoint tx")
	}

	spent, err := s.wallet.GetOutpointStatus(context.Background(), domain.Outpoint{
		Txid: txid,
		VOut: 0,
	})
	if err != nil {
		return err
	}

	if spent {
		log.Debugf("checkpoint output %s is spent, skipping scheduling sweep", txid)
		return nil
	}

	outputTaprootTapTree := ptx.Outputs[0].TaprootTapTree
	if len(outputTaprootTapTree) <= 0 {
		return fmt.Errorf("no taproot tap tree found in checkpoint tx")
	}

	checkpointTapscripts, err := txutils.DecodeTapTree(outputTaprootTapTree)
	if err != nil {
		return err
	}

	checkpointVtxoScript, err := script.ParseVtxoScript(checkpointTapscripts)
	if err != nil {
		return err
	}

	exitPaths := checkpointVtxoScript.ExitClosures()
	if len(exitPaths) != 1 {
		return fmt.Errorf(
			"invalid checkpoint tx: %s, found %d exit paths, expected 1",
			txid,
			len(exitPaths),
		)
	}

	sweepClosure, ok := exitPaths[0].(*script.CSVMultisigClosure)
	if !ok {
		return fmt.Errorf("exit path is not a csv multisig closure")
	}

	sweepAt := int64(0)
	if s.scheduler.Unit() == ports.BlockHeight {
		sweepAt = blockHeight + int64(sweepClosure.Locktime.Value)
	} else {
		sweepAt = blockTime + sweepClosure.Locktime.Seconds()
	}

	_, tapTree, err := checkpointVtxoScript.TapTree()
	if err != nil {
		return err
	}

	sweepTapscript, err := sweepClosure.Script()
	if err != nil {
		return err
	}

	sweepMerkleProof, err := tapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(sweepTapscript).TapHash(),
	)
	if err != nil {
		return err
	}

	execute := s.createCheckpointSweepTask(
		ports.SweepableOutput{
			Hash:         ptx.UnsignedTx.TxHash(),
			Index:        uint32(0), // checkpoint output is always the first one
			Script:       sweepMerkleProof.Script,
			ControlBlock: sweepMerkleProof.ControlBlock,
			InternalKey:  script.UnspendableKey(),
			Amount:       ptx.UnsignedTx.TxOut[0].Value,
		},
		vtxo,
	)

	// if the sweep checkpoint tapscript is availabe, execute the task immediately
	if !s.scheduler.AfterNow(sweepAt) {
		return execute()
	}

	if err := s.scheduleTask(sweeperTask{
		id:      txid,
		at:      sweepAt,
		execute: execute,
	}); err != nil {
		return err
	}

	return nil
}

// scheduleBatchSweep set up a task to be executed once at the given timestamp
func (s *sweeper) scheduleBatchSweep(
	expirationTimestamp int64, commitmentTxid string, vtxoTree *tree.TxTree,
) error {
	if vtxoTree == nil { // skip
		log.Debugf("skip scheduling sweep for batch %s:0, empty vtxo tree", commitmentTxid)
		return nil
	}

	if err := s.scheduleTask(sweeperTask{
		execute: s.createBatchSweepTask(commitmentTxid, vtxoTree),
		id:      vtxoTree.Root.UnsignedTx.TxID(),
		at:      expirationTimestamp,
	}); err != nil {
		return err
	}

	if err := s.updateVtxoExpirationTime(vtxoTree, expirationTimestamp); err != nil {
		log.WithError(err).Error("error while updating vtxo expiration time")
	}

	return nil
}

// TODO "combine" sweeper tasks execution into a single "sweep" to reduce the number of transactions to broadcast
func (s *sweeper) scheduleTask(task sweeperTask) error {
	if task.execute == nil {
		return nil
	}

	log.Debugf("scheduling sweeper task %s at %d", task.id, task.at)

	if !s.scheduler.AfterNow(task.at) {
		log.Debugf("trying to schedule task in the past, executing it immediately")
		return task.execute()
	}

	s.locker.Lock()
	defer s.locker.Unlock()

	if _, scheduled := s.scheduledTasks[task.id]; scheduled {
		return nil
	}

	s.scheduledTasks[task.id] = struct{}{}

	return s.scheduler.ScheduleTaskOnce(task.at, func() {
		log.Tracef("sweeper: %s", task.id)

		// check if the task is still scheduled before executing it
		s.locker.Lock()
		if _, scheduled := s.scheduledTasks[task.id]; !scheduled {
			log.Debugf("sweeper: task %s is not scheduled anymore, cancelling sweep", task.id)
			s.locker.Unlock()
			return
		}
		s.locker.Unlock()

		s.removeTask(task.id)

		if err := task.execute(); err != nil {
			log.WithError(err).Errorf("failed to execute sweeper task %s", task.id)
		}
	})
}

// createBatchSweepTask returns a function passed as handler in the scheduler
// it tries to craft a sweep tx containing the onchain outputs of the given vtxo tree
// if some parts of the tree have been broadcasted in the meantine, it will schedule the next taskes for the remaining parts of the tree
func (s *sweeper) createBatchSweepTask(
	commitmentTxid string, vtxoTree *tree.TxTree,
) func() error {
	return func() error {
		log.Debugf("start sweeping commitment tx %s", commitmentTxid)
		ctx := context.Background()
		round, err := s.repoManager.Rounds().GetRoundWithCommitmentTxid(ctx, commitmentTxid)
		if err != nil {
			return err
		}

		sweepInputs := make([]ports.SweepableOutput, 0)
		vtxoKeys := make([]domain.Outpoint, 0) // vtxos associated to the sweep inputs

		// inspect the vtxo tree to find onchain batch outputs
		batchOutputs, err := findSweepableOutputs(
			ctx, s.wallet, s.builder, s.scheduler.Unit(), vtxoTree,
		)
		if err != nil {
			return err
		}

		for expiredAt, inputs := range batchOutputs {
			// if the batch outputs are not expired, schedule a sweep task for it
			if s.scheduler.AfterNow(expiredAt) {
				subtrees, err := computeSubTrees(vtxoTree, inputs)
				if err != nil {
					log.WithError(err).Error("error while computing subtrees")
					continue
				}

				for _, subTree := range subtrees {
					if err := s.scheduleBatchSweep(expiredAt, commitmentTxid, subTree); err != nil {
						log.WithError(err).Error("error while scheduling sweep task")
						continue
					}
				}
				continue
			}

			// iterate over the expired batch outputs
			for _, input := range inputs {
				// sweepableVtxos related to the sweep input
				sweepableVtxos := make([]domain.Outpoint, 0)

				// check if input is the vtxo itself
				// TODO: we never arrive to sweep directly the leaf tx, we sweep the parent one in
				// worst case, so this check can be dropped.
				vtxos, _ := s.repoManager.Vtxos().GetVtxos(
					ctx,
					[]domain.Outpoint{
						{
							Txid: input.Hash.String(),
							VOut: input.Index,
						},
					},
				)
				if len(vtxos) > 0 {
					if !vtxos[0].Swept && !vtxos[0].Unrolled {
						sweepableVtxos = append(sweepableVtxos, vtxos[0].Outpoint)
					}
				} else {
					// if it's not a vtxo, find all the vtxos leaves reachable from that input
					vtxosLeaves, err := findLeaves(vtxoTree, input.Hash.String(), input.Index)
					if err != nil {
						log.WithError(err).Error("error while finding vtxos leaves")
						continue
					}

					for _, leaf := range vtxosLeaves {
						vtxo := domain.Outpoint{
							Txid: leaf.UnsignedTx.TxID(),
							VOut: 0,
						}

						sweepableVtxos = append(sweepableVtxos, vtxo)
					}

					if len(sweepableVtxos) <= 0 {
						continue
					}

					firstVtxo, err := s.repoManager.Vtxos().GetVtxos(ctx, sweepableVtxos[:1])
					if err != nil {
						log.WithError(err).Errorf("failed to get vtxo %s", sweepableVtxos[0])
						sweepInputs = append(sweepInputs, input) // add the input anyway in order to try to sweep it
						continue
					}
					if len(firstVtxo) <= 0 {
						log.Errorf("vtxo %s not found", sweepableVtxos[0])
						continue
					}

					if firstVtxo[0].Swept || firstVtxo[0].Unrolled {
						// we assume that if the first vtxo is swept or unrolled, the batch output has been spent
						// skip, the output is already swept or spent by a unilateral exit
						continue
					}
				}

				if len(sweepableVtxos) > 0 {
					vtxoKeys = append(vtxoKeys, sweepableVtxos...)
					sweepInputs = append(sweepInputs, input)
				}
			}
		}

		if len(sweepInputs) > 0 {
			// build the sweep transaction with all the expired non-swept batch outputs
			sweepTxId, sweepTx, err := s.builder.BuildSweepTx(sweepInputs)
			if err != nil {
				return err
			}

			// check if the transaction is already onchain
			tx, _ := s.wallet.GetTransaction(ctx, sweepTxId)

			txid := ""

			if len(tx) > 0 {
				txid = sweepTxId
			}

			err = nil
			// retry until the tx is broadcasted or the error is not BIP68 final
			for len(txid) == 0 && (err == nil || err == ports.ErrNonFinalBIP68) {
				if err != nil {
					log.Debugln("sweep tx not BIP68 final, retrying in 5 seconds")
					time.Sleep(5 * time.Second)
				}

				txid, err = s.wallet.BroadcastTransaction(ctx, sweepTx)
			}
			if err != nil {
				return err
			}

			if len(txid) > 0 {
				log.Debugln("sweep tx broadcasted:", txid)

				events, err := round.Sweep(vtxoKeys, txid, sweepTx)
				if err != nil {
					return err
				}
				if len(events) > 0 {
					if err := s.repoManager.Events().Save(
						ctx, domain.RoundTopic, round.Id, events,
					); err != nil {
						return err
					}
				}
			}
		}

		return nil
	}
}

func (s *sweeper) createCheckpointSweepTask(
	toSweep ports.SweepableOutput, vtxo domain.Outpoint,
) func() error {
	return func() error {
		log.Debugf("start sweeping checkpoint output %s", toSweep.Hash.String())
		_, sweepTx, err := s.builder.BuildSweepTx([]ports.SweepableOutput{toSweep})
		if err != nil {
			return err
		}

		txid, err := s.wallet.BroadcastTransaction(context.Background(), sweepTx)
		if err != nil {
			return err
		}

		if len(txid) > 0 {
			log.Debugln("sweep tx broadcasted:", txid)
		}

		return s.repoManager.Vtxos().SweepVtxos(context.Background(), []domain.Outpoint{vtxo})
	}
}

func (s *sweeper) updateVtxoExpirationTime(
	tree *tree.TxTree, expirationTime int64,
) error {
	leaves := tree.Leaves()
	vtxos := make([]domain.Outpoint, 0)

	for _, leaf := range leaves {
		vtxo, err := extractVtxoOutpoint(leaf)
		if err != nil {
			return err
		}

		vtxos = append(vtxos, *vtxo)
	}

	return s.repoManager.Vtxos().UpdateVtxosExpiration(context.Background(), vtxos, expirationTime)
}

func computeSubTrees(
	vtxoTree *tree.TxTree, inputs []ports.SweepableOutput,
) ([]*tree.TxTree, error) {
	subTrees := make(map[string]*tree.TxTree, 0)

	// for each sweepable input, create a sub vtxo tree
	// it allows to skip the part of the tree that has been broadcasted in the next task
	for _, input := range inputs {
		if subTree := vtxoTree.Find(input.Hash.String()); subTree != nil {
			rootTxid := subTree.Root.UnsignedTx.TxID()
			subTrees[rootTxid] = subTree
		}
	}

	// filter out the sub trees, remove the ones that are included in others
	filteredSubTrees := make([]*tree.TxTree, 0)
	for i, subTree := range subTrees {
		notIncludedInOtherTrees := true

		for j, otherSubTree := range subTrees {
			if i == j {
				continue
			}
			contains, err := containsTree(otherSubTree, subTree)
			if err != nil {
				log.WithError(err).Error("error while checking nested trees")
				continue
			}

			if contains {
				notIncludedInOtherTrees = false
				break
			}
		}

		if notIncludedInOtherTrees {
			filteredSubTrees = append(filteredSubTrees, subTree)
		}
	}

	return filteredSubTrees, nil
}

func containsTree(tr0 *tree.TxTree, tr1 *tree.TxTree) (bool, error) {
	if tr0 == nil || tr1 == nil {
		return false, nil
	}

	tr1RootTxid := tr1.Root.UnsignedTx.TxID()

	// Check if tr1's root exists in tr0
	found := tr0.Find(tr1RootTxid)
	return found != nil, nil
}

func findLeaves(txTree *tree.TxTree, fromtxid string, vout uint32) ([]*psbt.Packet, error) {
	var foundParent *tree.TxTree

	if err := txTree.Apply(func(g *tree.TxTree) (bool, error) {
		parent := g.Root.UnsignedTx.TxIn[0].PreviousOutPoint
		if parent.Hash.String() == fromtxid && parent.Index == vout {
			foundParent = g
			return false, nil
		}

		return true, nil
	}); err != nil {
		return nil, err
	}

	if foundParent == nil {
		return nil, fmt.Errorf("tx %s not found in the tx tree", fromtxid)
	}

	return foundParent.Leaves(), nil
}

func extractVtxoOutpoint(leaf *psbt.Packet) (*domain.Outpoint, error) {
	// Find the first non-anchor output
	for i, out := range leaf.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) {
			continue
		}

		return &domain.Outpoint{
			Txid: leaf.UnsignedTx.TxID(),
			VOut: uint32(i),
		}, nil
	}

	return nil, fmt.Errorf("no non-anchor output found in leaf")
}
