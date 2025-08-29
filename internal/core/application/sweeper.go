package application

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
)

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
	locker         *sync.Mutex
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

	if len(sweepableBatches) > 0 {
		log.Infof("sweeper: restoring %d sweepable batches", len(sweepableBatches))

		progress := 0.0
		count := 0
		for _, txid := range sweepableBatches {
			flatVtxoTree, err := s.repoManager.Rounds().GetRoundVtxoTree(ctx, txid)
			if err != nil {
				return err
			}

			if len(flatVtxoTree) <= 0 {
				continue
			}

			vtxoTree, err := tree.NewTxTree(flatVtxoTree)
			if err != nil {
				return err
			}

			task := s.createTask(txid, vtxoTree)
			task()

			newProgress := (1.0 / float64(len(sweepableBatches))) + progress
			if int(newProgress*100) > int(progress*100) {
				progress = newProgress
				log.Infof("sweeper: restoring... %d%%", int(progress*100))
			}
			count++
		}

		log.Infof("sweeper: scheduled sweeping for %d batches", count)
	}

	return nil
}

func (s *sweeper) stop() {
	s.scheduler.Stop()
}

// removeTask update the cached map of scheduled tasks
func (s *sweeper) removeTask(treeRootTxid string) {
	s.locker.Lock()
	defer s.locker.Unlock()
	delete(s.scheduledTasks, treeRootTxid)
}

// schedule set up a task to be executed once at the given timestamp
func (s *sweeper) schedule(
	expirationTimestamp int64, commitmentTxid string, vtxoTree *tree.TxTree,
) error {
	if vtxoTree == nil { // skip
		log.Debugf("skip shceduling sweep for batch %s:0, empty vtxo tree", commitmentTxid)
		return nil
	}

	rootTxid := vtxoTree.Root.UnsignedTx.TxID()

	if _, scheduled := s.scheduledTasks[rootTxid]; scheduled {
		return nil
	}

	task := s.createTask(commitmentTxid, vtxoTree)

	if err := s.scheduler.ScheduleTaskOnce(expirationTimestamp, task); err != nil {
		return err
	}

	s.locker.Lock()
	s.scheduledTasks[rootTxid] = struct{}{}
	s.locker.Unlock()

	if err := s.updateVtxoExpirationTime(vtxoTree, expirationTimestamp); err != nil {
		log.WithError(err).Error("error while updating vtxo expiration time")
	}

	return nil
}

// createTask returns a function passed as handler in the scheduler
// it tries to craft a sweep tx containing the onchain outputs of the given vtxo tree
// if some parts of the tree have been broadcasted in the meantine, it will schedule the next taskes for the remaining parts of the tree
func (s *sweeper) createTask(
	commitmentTxid string, vtxoTree *tree.TxTree,
) func() {
	return func() {
		ctx := context.Background()
		rootTxid := vtxoTree.Root.UnsignedTx.TxID()
		round, err := s.repoManager.Rounds().GetRoundWithCommitmentTxid(ctx, commitmentTxid)
		if err != nil {
			log.WithError(err).Error("failed to get round")
			return
		}

		s.removeTask(rootTxid)
		log.Tracef("sweeper: %s", rootTxid)

		sweepInputs := make([]ports.SweepableBatchOutput, 0)
		vtxoKeys := make([]domain.Outpoint, 0) // vtxos associated to the sweep inputs

		// inspect the vtxo tree to find onchain batch outputs
		batchOutputs, err := findSweepableOutputs(
			ctx, s.wallet, s.builder, s.scheduler.Unit(), vtxoTree,
		)
		if err != nil {
			log.WithError(err).Error("error while inspecting vtxo tree")
			return
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
					if err := s.schedule(expiredAt, commitmentTxid, subTree); err != nil {
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
							Txid: input.GetHash().String(),
							VOut: input.GetIndex(),
						},
					},
				)
				if len(vtxos) > 0 {
					if !vtxos[0].Swept && !vtxos[0].Unrolled {
						sweepableVtxos = append(sweepableVtxos, vtxos[0].Outpoint)
					}
				} else {
					// if it's not a vtxo, find all the vtxos leaves reachable from that input
					vtxosLeaves, err := findLeaves(vtxoTree, input.GetHash().String(), input.GetIndex())
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
				log.WithError(err).Error("error while building sweep tx")
				return
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
				log.WithError(err).Error("error while broadcasting sweep tx")
				return
			}

			if len(txid) > 0 {
				log.Debugln("sweep tx broadcasted:", txid)

				events, err := round.Sweep(vtxoKeys, txid, sweepTx)
				if err != nil {
					log.WithError(err).Error("failed to sweep batch")
					return
				}
				if len(events) > 0 {
					if err := s.repoManager.Events().Save(
						ctx, domain.RoundTopic, round.Id, events,
					); err != nil {
						log.WithError(err).Errorf(
							"failed to save sweep events for round %s", commitmentTxid,
						)
						return
					}
				}
			}
		}
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
	vtxoTree *tree.TxTree, inputs []ports.SweepableBatchOutput,
) ([]*tree.TxTree, error) {
	subTrees := make(map[string]*tree.TxTree, 0)

	// for each sweepable input, create a sub vtxo tree
	// it allows to skip the part of the tree that has been broadcasted in the next task
	for _, input := range inputs {
		if subTree := vtxoTree.Find(input.GetHash().String()); subTree != nil {
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
