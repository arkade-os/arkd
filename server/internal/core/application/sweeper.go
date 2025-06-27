package application

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
)

// sweeper is an unexported service running while the main application service is started
// it is responsible for sweeping onchain shared outputs that expired
// it also handles delaying the sweep events in case some parts of the tree are broadcasted
// when a round is finalized, the main application service schedules a sweep event on the newly created vtxo tree
type sweeper struct {
	wallet      ports.WalletService
	repoManager ports.RepoManager
	builder     ports.TxBuilder
	scheduler   ports.SchedulerService

	noteUriPrefix string

	// cache of scheduled tasks, avoid scheduling the same sweep event multiple times
	locker         sync.Locker
	scheduledTasks map[string]struct{}
}

func newSweeper(
	wallet ports.WalletService,
	repoManager ports.RepoManager,
	builder ports.TxBuilder,
	scheduler ports.SchedulerService,
	noteUriPrefix string,
) *sweeper {
	return &sweeper{
		wallet,
		repoManager,
		builder,
		scheduler,
		noteUriPrefix,
		&sync.Mutex{},
		make(map[string]struct{}),
	}
}

func (s *sweeper) start() error {
	s.scheduler.Start()

	ctx := context.Background()

	unsweptRounds, err := s.repoManager.Rounds().GetUnsweptRoundsTxid(ctx)
	if err != nil {
		return err
	}

	if len(unsweptRounds) > 0 {
		log.Infof("sweeper: restoring %d unswept batches", len(unsweptRounds))

		progress := 0.0

		for _, txid := range unsweptRounds {
			graphChunks, err := s.repoManager.Rounds().GetVtxoTreeWithTxid(ctx, txid)
			if err != nil {
				return err
			}

			if len(graphChunks) <= 0 {
				continue
			}

			graph, err := tree.NewTxGraph(graphChunks)
			if err != nil {
				return err
			}

			task := s.createTask(txid, graph)
			task()

			newProgress := (1.0 / float64(len(unsweptRounds))) + progress
			if int(newProgress*100) > int(progress*100) {
				progress = newProgress
				log.Infof("sweeper: restoring... %d%%", int(progress*100))
			}
		}

		log.Infof("sweeper: unswept batches restored")
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
	expirationTimestamp int64, roundTxid string, graph *tree.TxGraph,
) error {
	if graph == nil { // skip
		log.Debugf("skipping sweep scheduling (round tx %s), empty vtxo tree", roundTxid)
		return nil
	}

	rootTxid := graph.Root.UnsignedTx.TxID()

	if _, scheduled := s.scheduledTasks[rootTxid]; scheduled {
		return nil
	}

	task := s.createTask(roundTxid, graph)

	if err := s.scheduler.ScheduleTaskOnce(expirationTimestamp, task); err != nil {
		return err
	}

	s.locker.Lock()
	s.scheduledTasks[rootTxid] = struct{}{}
	s.locker.Unlock()

	if err := s.updateVtxoExpirationTime(graph, expirationTimestamp); err != nil {
		log.WithError(err).Error("error while updating vtxo expiration time")
	}

	return nil
}

// createTask returns a function passed as handler in the scheduler
// it tries to craft a sweep tx containing the onchain outputs of the given vtxo tree
// if some parts of the tree have been broadcasted in the meantine, it will schedule the next taskes for the remaining parts of the tree
func (s *sweeper) createTask(
	roundTxid string, vtxoTree *tree.TxGraph,
) func() {
	return func() {
		ctx := context.Background()
		rootTxid := vtxoTree.Root.UnsignedTx.TxID()

		s.removeTask(rootTxid)
		log.Tracef("sweeper: %s", rootTxid)

		sweepInputs := make([]ports.SweepInput, 0)
		vtxoKeys := make([]domain.Outpoint, 0) // vtxos associated to the sweep inputs

		// inspect the vtxo tree to find onchain shared outputs
		sharedOutputs, err := findSweepableOutputs(ctx, s.wallet, s.builder, s.scheduler.Unit(), vtxoTree)
		if err != nil {
			log.WithError(err).Error("error while inspecting vtxo tree")
			return
		}

		for expiredAt, inputs := range sharedOutputs {
			// if the shared outputs are not expired, schedule a sweep task for it
			if s.scheduler.AfterNow(expiredAt) {
				subtrees, err := computeSubTrees(vtxoTree, inputs)
				if err != nil {
					log.WithError(err).Error("error while computing subtrees")
					continue
				}

				for _, subTree := range subtrees {
					if err := s.schedule(expiredAt, roundTxid, subTree); err != nil {
						log.WithError(err).Error("error while scheduling sweep task")
						continue
					}
				}
				continue
			}

			// iterate over the expired shared outputs
			for _, input := range inputs {
				// sweepableVtxos related to the sweep input
				sweepableVtxos := make([]domain.Outpoint, 0)

				// check if input is the vtxo itself
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
					if !vtxos[0].Swept && !vtxos[0].Redeemed {
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
						log.Error(fmt.Errorf("error while getting vtxo: %w", err))
						sweepInputs = append(sweepInputs, input) // add the input anyway in order to try to sweep it
						continue
					}

					if firstVtxo[0].Swept || firstVtxo[0].Redeemed {
						// we assume that if the first vtxo is swept or redeemed, the shared output has been spent
						// skip, the output is already swept or spent by a unilateral redeem
						continue
					}
				}

				if len(sweepableVtxos) > 0 {
					vtxoKeys = append(vtxoKeys, sweepableVtxos...)
					sweepInputs = append(sweepInputs, input)
				}
			}
		}

		vtxosRepository := s.repoManager.Vtxos()
		if len(sweepInputs) > 0 {
			// build the sweep transaction with all the expired non-swept shared outputs
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

				// mark the vtxos as swept
				if err := vtxosRepository.SweepVtxos(ctx, vtxoKeys); err != nil {
					log.Error(fmt.Errorf("error while deleting vtxos: %w", err))
					return
				}

				log.Debugf("%d vtxos swept", len(vtxoKeys))
			}
		}

		roundVtxos, err := vtxosRepository.GetVtxosForRound(ctx, roundTxid)
		if err != nil {
			log.WithError(err).Error("error while getting vtxos for round")
			return
		}

		allSwept := true
		for _, vtxo := range roundVtxos {
			allSwept = allSwept && (vtxo.Swept || vtxo.Redeemed)
			if !allSwept {
				break
			}
		}

		if allSwept {
			// update the round
			roundRepo := s.repoManager.Rounds()
			round, err := roundRepo.GetRoundWithTxid(ctx, roundTxid)
			if err != nil {
				log.WithError(err).Error("error while getting round")
				return
			}

			log.Debugf("round %s fully swept", roundTxid)
			round.Sweep()

			if err := roundRepo.AddOrUpdateRound(ctx, *round); err != nil {
				log.WithError(err).Error("error while marking round as swept")
				return
			}
		}
	}
}

func (s *sweeper) updateVtxoExpirationTime(
	tree *tree.TxGraph,
	expirationTime int64,
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

	return s.repoManager.Vtxos().UpdateExpireAt(context.Background(), vtxos, expirationTime)
}

func computeSubTrees(vtxoTree *tree.TxGraph, inputs []ports.SweepInput) ([]*tree.TxGraph, error) {
	subTrees := make(map[string]*tree.TxGraph, 0)

	// for each sweepable input, create a sub vtxo tree
	// it allows to skip the part of the tree that has been broadcasted in the next task
	for _, input := range inputs {
		subTree, err := computeSubTree(vtxoTree, input.GetHash().String())
		if err != nil {
			log.WithError(err).Error("error while finding sub tree")
			continue
		}

		if subTree != nil {
			rootTxid := subTree.Root.UnsignedTx.TxID()
			subTrees[rootTxid] = subTree
		}
	}

	// filter out the sub trees, remove the ones that are included in others
	filteredSubTrees := make([]*tree.TxGraph, 0)
	for i, subTree := range subTrees {
		notIncludedInOtherTrees := true

		for j, otherSubTree := range subTrees {
			if i == j {
				continue
			}
			contains, err := containsTree(otherSubTree, subTree)
			if err != nil {
				log.WithError(err).Error("error while checking if a tree contains another")
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

func computeSubTree(vtxoTree *tree.TxGraph, newRoot string) (*tree.TxGraph, error) {
	// Find the subgraph starting from the newRoot
	foundGraph := vtxoTree.Find(newRoot)
	if foundGraph != nil {
		return foundGraph, nil
	}

	// If not found, return nil (no subtree to create)
	return nil, nil
}

func containsTree(tr0 *tree.TxGraph, tr1 *tree.TxGraph) (bool, error) {
	if tr0 == nil || tr1 == nil {
		return false, nil
	}

	tr1RootTxid := tr1.Root.UnsignedTx.TxID()

	// Check if tr1's root exists in tr0
	found := tr0.Find(tr1RootTxid)
	return found != nil, nil
}

func findLeaves(graph *tree.TxGraph, fromtxid string, vout uint32) ([]*psbt.Packet, error) {
	var foundParent *tree.TxGraph

	if err := graph.Apply(func(g *tree.TxGraph) (bool, error) {
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
		return nil, fmt.Errorf("no tx %s found in the graph", fromtxid)
	}

	return foundParent.Leaves(), nil
}

func extractVtxoOutpoint(leaf *psbt.Packet) (*domain.Outpoint, error) {
	// Find the first non-anchor output
	for i, out := range leaf.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, tree.ANCHOR_PKSCRIPT) {
			continue
		}

		return &domain.Outpoint{
			Txid: leaf.UnsignedTx.TxID(),
			VOut: uint32(i),
		}, nil
	}

	return nil, fmt.Errorf("no non-anchor output found in leaf")
}
