package _5_aggrelite

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	channeltypes "github.com/T-ragon/ibc-go/v9/modules/core/04-channel/types"
	"hash"
	"sort"
	"strings"
	"time"

	ics23 "github.com/cosmos/ics23/go"

	errorsmod "cosmossdk.io/errors"
	storetypes "cosmossdk.io/store/types"
	"github.com/T-ragon/ibc-go/v9/modules/core/04-channel/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cometbft/cometbft/light"
	tmtypes "github.com/cometbft/cometbft/types"

	clienttypes "github.com/T-ragon/ibc-go/v9/modules/core/02-client/types"
	commitmenttypes "github.com/T-ragon/ibc-go/v9/modules/core/23-commitment/types"
	ibcerrors "github.com/T-ragon/ibc-go/v9/modules/core/errors"
	"github.com/T-ragon/ibc-go/v9/modules/core/exported"
)

var _ exported.ClientState = (*ClientState)(nil)

// NewClientState creates a new ClientState instance
func NewClientState(
	chainID string, trustLevel Fraction,
	trustingPeriod, ubdPeriod, maxClockDrift time.Duration,
	latestHeight clienttypes.Height, specs []*ics23.ProofSpec,
	upgradePath []string,
) *ClientState {
	return &ClientState{
		ChainId:         chainID,
		TrustLevel:      trustLevel,
		TrustingPeriod:  trustingPeriod,
		UnbondingPeriod: ubdPeriod,
		MaxClockDrift:   maxClockDrift,
		LatestHeight:    latestHeight,
		FrozenHeight:    clienttypes.ZeroHeight(),
		ProofSpecs:      specs,
		UpgradePath:     upgradePath,
	}
}

// GetChainID returns the chain-id
func (cs ClientState) GetChainID() string {
	return cs.ChainId
}

// ClientType is aggrelite.
func (ClientState) ClientType() string {
	return exported.AggreLite
}

// GetLatestHeight returns latest block height.
func (cs ClientState) GetLatestHeight() exported.Height {
	return cs.LatestHeight
}

// GetTimestampAtHeight returns the timestamp in nanoseconds of the consensus state at the given height.
func (ClientState) GetTimestampAtHeight(
	ctx sdk.Context,
	clientStore storetypes.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
) (uint64, error) {
	// get consensus state at height from clientStore to check for expiry
	consState, found := GetConsensusState(clientStore, cdc, height)
	if !found {
		return 0, errorsmod.Wrapf(clienttypes.ErrConsensusStateNotFound, "height (%s)", height)
	}
	return consState.GetTimestamp(), nil
}

// Status returns the status of the aggrelite client.
// The client may be:
// - Active: FrozenHeight is zero and client is not expired
// - Frozen: Frozen Height is not zero
// - Expired: the latest consensus state timestamp + trusting period <= current time
//
// A frozen client will become expired, so the Frozen status
// has higher precedence.
func (cs ClientState) Status(
	ctx sdk.Context,
	clientStore storetypes.KVStore,
	cdc codec.BinaryCodec,
) exported.Status {
	if !cs.FrozenHeight.IsZero() {
		return exported.Frozen
	}

	// get latest consensus state from clientStore to check for expiry
	consState, found := GetConsensusState(clientStore, cdc, cs.GetLatestHeight())
	if !found {
		// if the client state does not have an associated consensus state for its latest height
		// then it must be expired
		return exported.Expired
	}

	if cs.IsExpired(consState.Timestamp, ctx.BlockTime()) {
		return exported.Expired
	}

	return exported.Active
}

// IsExpired returns whether or not the client has passed the trusting period since the last
// update (in which case no headers are considered valid).
func (cs ClientState) IsExpired(latestTimestamp, now time.Time) bool {
	expirationTime := latestTimestamp.Add(cs.TrustingPeriod)
	return !expirationTime.After(now)
}

// Validate performs a basic validation of the client state fields.
func (cs ClientState) Validate() error {
	if strings.TrimSpace(cs.ChainId) == "" {
		return errorsmod.Wrap(ErrInvalidChainID, "chain id cannot be empty string")
	}

	// NOTE: the value of tmtypes.MaxChainIDLen may change in the future.
	// If this occurs, the code here must account for potential difference
	// between the aggrelite version being run by the counterparty chain
	// and the aggrelite version used by this light client.
	// https://github.com/cosmos/ibc-go/issues/177
	if len(cs.ChainId) > tmtypes.MaxChainIDLen {
		return errorsmod.Wrapf(ErrInvalidChainID, "chainID is too long; got: %d, max: %d", len(cs.ChainId), tmtypes.MaxChainIDLen)
	}

	if err := light.ValidateTrustLevel(cs.TrustLevel.ToAggrelite()); err != nil {
		return err
	}
	if cs.TrustingPeriod <= 0 {
		return errorsmod.Wrap(ErrInvalidTrustingPeriod, "trusting period must be greater than zero")
	}
	if cs.UnbondingPeriod <= 0 {
		return errorsmod.Wrap(ErrInvalidUnbondingPeriod, "unbonding period must be greater than zero")
	}
	if cs.MaxClockDrift <= 0 {
		return errorsmod.Wrap(ErrInvalidMaxClockDrift, "max clock drift must be greater than zero")
	}

	// the latest height revision number must match the chain id revision number
	if cs.LatestHeight.RevisionNumber != clienttypes.ParseChainID(cs.ChainId) {
		return errorsmod.Wrapf(ErrInvalidHeaderHeight,
			"latest height revision number must match chain id revision number (%d != %d)", cs.LatestHeight.RevisionNumber, clienttypes.ParseChainID(cs.ChainId))
	}
	if cs.LatestHeight.RevisionHeight == 0 {
		return errorsmod.Wrapf(ErrInvalidHeaderHeight, "aggrelite client's latest height revision height cannot be zero")
	}
	if cs.TrustingPeriod >= cs.UnbondingPeriod {
		return errorsmod.Wrapf(
			ErrInvalidTrustingPeriod,
			"trusting period (%s) should be < unbonding period (%s)", cs.TrustingPeriod, cs.UnbondingPeriod,
		)
	}

	if cs.ProofSpecs == nil {
		return errorsmod.Wrap(ErrInvalidProofSpecs, "proof specs cannot be nil for tm client")
	}
	for i, spec := range cs.ProofSpecs {
		if spec == nil {
			return errorsmod.Wrapf(ErrInvalidProofSpecs, "proof spec cannot be nil at index: %d", i)
		}
	}
	// UpgradePath may be empty, but if it isn't, each key must be non-empty
	for i, k := range cs.UpgradePath {
		if strings.TrimSpace(k) == "" {
			return errorsmod.Wrapf(clienttypes.ErrInvalidClient, "key in upgrade path at index %d cannot be empty", i)
		}
	}

	return nil
}

// ZeroCustomFields returns a ClientState that is a copy of the current ClientState
// with all client customizable fields zeroed out
func (cs ClientState) ZeroCustomFields() exported.ClientState {
	// copy over all chain-specified fields
	// and leave custom fields empty
	return &ClientState{
		ChainId:         cs.ChainId,
		UnbondingPeriod: cs.UnbondingPeriod,
		LatestHeight:    cs.LatestHeight,
		ProofSpecs:      cs.ProofSpecs,
		UpgradePath:     cs.UpgradePath,
	}
}

// Initialize checks that the initial consensus state is an 05-aggrelite consensus state and
// sets the client state, consensus state and associated metadata in the provided client store.
func (cs ClientState) Initialize(ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore, consState exported.ConsensusState) error {
	consensusState, ok := consState.(*ConsensusState)
	if !ok {
		return errorsmod.Wrapf(clienttypes.ErrInvalidConsensus, "invalid initial consensus state. expected type: %T, got: %T",
			&ConsensusState{}, consState)
	}

	setClientState(clientStore, cdc, &cs)
	setConsensusState(clientStore, cdc, consensusState, cs.GetLatestHeight())
	setConsensusMetadata(ctx, clientStore, cs.GetLatestHeight())

	return nil
}

func (cs ClientState) SetHashValue(ctx sdk.Context, key []byte, value []byte, clientStore storetypes.KVStore) {

}

// VerifyAggregateMembership is a generic proof verification method which verifies a proof of the existence of a value at a given CommitmentPath at the specified height.
// The caller is expected to construct the full CommitmentPath from a CommitmentPrefix and a standardized path (as defined in ICS 24).
// If a zero proof height is passed in, it will fail to retrieve the associated consensus state.
func (cs ClientState) VerifyAggregateMembership(
	ctx sdk.Context,
	clientStore storetypes.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	delayTimePeriod uint64,
	delayBlockPeriod uint64,
	keyArr [][]byte,
	leafNumber []uint64,
	values [][]byte,
	proof [][]byte,
	leafOps [][]byte) error {
	ctx.Logger().Info("**********************************************聚合验证函数第四层***********************************************")
	if cs.GetLatestHeight().LT(height) {
		return errorsmod.Wrapf(
			ibcerrors.ErrInvalidHeight,
			"client state height < proof height (%d < %d), please ensure the client has been updated", cs.GetLatestHeight(), height,
		)
	}
	if err := verifyDelayPeriodPassed(ctx, clientStore, height, delayTimePeriod, delayBlockPeriod); err != nil {
		return err
	}

	consensusState, found := GetConsensusState(clientStore, cdc, height)
	if !found {
		return errorsmod.Wrap(clienttypes.ErrConsensusStateNotFound, "please ensure the proof was constructed against a height that exists on the client")
	}

	return verifyAggregateProof(ctx, cdc, leafNumber, values, proof, consensusState.Root.Hash, keyArr, leafOps)
}

// doHash will preform the specified hash on the preimage.
// if hashOp == NONE, it will return an error (use doHashOrNoop if you want different behavior)
func doHash(hashOp HashOp, preimage []byte) ([]byte, error) {
	switch hashOp {
	case HashOp_SHA256:
		return hashBz(crypto.SHA256, preimage)
	case HashOp_SHA512:
		return hashBz(crypto.SHA512, preimage)
	case HashOp_RIPEMD160:
		return hashBz(crypto.RIPEMD160, preimage)
	case HashOp_BITCOIN:
		// ripemd160(sha256(x))
		sha := crypto.SHA256.New()
		sha.Write(preimage)
		tmp := sha.Sum(nil)
		hash := crypto.RIPEMD160.New()
		hash.Write(tmp)
		return hash.Sum(nil), nil
	case HashOp_SHA512_256:
		hash := crypto.SHA512_256.New()
		hash.Write(preimage)
		return hash.Sum(nil), nil
	}
	return nil, fmt.Errorf("unsupported hashop: %d", hashOp)
}

func extractRightFromInnerOp(rop *channeltypes.InnerOp) ([]byte, error) {
	if len(rop.Suffix) == 0 {
		return nil, errors.New("suffix is empty, no right value")
	}

	lengthByte := byte(0x20)
	suffix := rop.Suffix

	//check if suffix starts with lengthByte
	if suffix[0] != lengthByte {
		return nil, errors.New("suffix length does not match")
	}

	//extract the right value
	right := suffix[1:]

	return right, nil
}

func checkInnerOpIsContainBytes(iop *channeltypes.InnerOp, value []byte) (error, bool) {
	if len(iop.Suffix) == 0 {
		left := iop.Prefix[:len(iop.Prefix)-1]
		leftstr := string(left)
		return nil, strings.HasSuffix(leftstr, string(value))
	} else {
		rightstr := string(iop.Suffix)
		return nil, strings.HasSuffix(rightstr, string(value))
	}
}

type hasher interface {
	New() hash.Hash
}

func hashBz(h hasher, preimage []byte) ([]byte, error) {
	hh := h.New()
	hh.Write(preimage)
	return hh.Sum(nil), nil
}

func calculateLeafs(values [][]byte, leafOp []*ics23.LeafOp, key [][]byte) [][]byte {
	res := make([][]byte, len(values))
	for i, value := range values {
		res[i], _ = leafOp[i].Apply(key[i], value)
	}
	return res
}

func calculateLeaf(values [][]byte, leafOp *ics23.LeafOp, key [][]byte) [][]byte {
	res := make([][]byte, len(values))
	for i, value := range values {
		res[i], _ = leafOp.Apply(key[i], value)
	}
	return res
}

func MainVerifyAggregateProof(
	leafNumber []uint64,
	values [][]byte,
	key [][]byte,
	leafOp ics23.LeafOp,
	subProofs []*types.SubProof,
	root []byte) (error, bool) {
	fmt.Println("values", values)
	// 结合 leafNumber 检查values是否存在于subProofs
	values = calculateLeaf(values, &leafOp, key)
	fmt.Println("修改后的values", values)
	subproofMap := make(map[uint64]*types.SubProof)
	for _, subProof := range subProofs {
		subproofMap[subProof.Number] = subProof
	}

	for j, value := range values {
		subProof := subproofMap[leafNumber[j]]
		found := false
		if subProof != nil {
			for _, proofMeta := range subProof.ProofMetaList {
				meta1 := proofMeta.HashValue
				fmt.Println(meta1)
				err, contains := checkInnerOpIsContainBytes(proofMeta.PathInnerOp, value)
				if err != nil {
					return err, false
				}
				if bytes.Equal(meta1, value) || contains {
					found = true
					break
				}
			}
			if !found {
				return errorsmod.Wrapf(ErrInvalidProofSpecs, "failed to find subproof for leaf"), false
			}
		}
	}

	// 对SubProof原地排序
	sort.Slice(subProofs, func(i, j int) bool {
		return subProofs[i].Number > subProofs[j].Number
	})

	for i := 0; i < len(subProofs)-2; i++ {
		currentProof := subProofs[i]
		nextProof := subProofs[i+1]
		for _, proofMeta := range currentProof.ProofMetaList {
			meta1 := proofMeta.HashValue
			if len(proofMeta.RealValue) != 0 {
				meta1 = proofMeta.RealValue
			}
			fmt.Println(meta1)
			preimage := proofMeta.PathInnerOp.Prefix
			preimage = append(preimage, meta1...)
			preimage = append(preimage, proofMeta.PathInnerOp.Suffix...)
			combinedHash, err := doHash(HashOp_SHA256, preimage)
			fmt.Println("第", currentProof.Number, combinedHash)
			if err != nil {
				return err, false
			}
			found := false
			for _, nextProofMeta := range nextProof.ProofMetaList {
				meta1_netxt := nextProofMeta.HashValue
				_, contains := checkInnerOpIsContainBytes(nextProofMeta.PathInnerOp, combinedHash)
				if bytes.Equal(combinedHash, meta1_netxt) || contains {
					found = true
					break
				}
			}
			if !found {
				fmt.Println("2222222222222222222")
				return errorsmod.Wrapf(ErrInvalidProofSpecs, "failed to find subProof in  next level "), false
			}
		}
	}

	//最后一层只有两个结点
	finalSubProof := subProofs[len(subProofs)-1].ProofMetaList
	for _, proofMeta := range finalSubProof {
		meta1 := proofMeta.HashValue
		preimage := proofMeta.PathInnerOp.Prefix
		preimage = append(preimage, meta1...)
		preimage = append(preimage, proofMeta.PathInnerOp.Suffix...)
		combinedHash, err := doHash(HashOp_SHA256, preimage)
		if err != nil {
			return err, false
		}
		fmt.Println(combinedHash)
		if bytes.Equal(root, combinedHash) {
			fmt.Println("Verified Successfully!")
			return nil, true
		}
	}
	fmt.Println("111111111111111111111")
	return errorsmod.Wrapf(ErrInvalidProofSpecs, "failed to find subProof for leaf "), false
}

func toIcs23(leafOp *types.LeafOp) *ics23.LeafOp {
	return &ics23.LeafOp{
		Hash:         ics23.HashOp(leafOp.Hash),
		PrehashKey:   ics23.HashOp(leafOp.PrehashKey),
		PrehashValue: ics23.HashOp(leafOp.PrehashValue),
		Length:       ics23.LengthOp(leafOp.Length),
		Prefix:       leafOp.Prefix,
	}
}

func unMarshaSubProof(cdc codec.BinaryCodec, bytes [][]byte, subProofs []*channeltypes.SubProof) {
	for i, subProof := range bytes {
		err := subProofs[i].Unmarshal(subProof)
		if err != nil {
			panic(errors.New("failed to unmarshal subProof"))
		}
	}
}

func unMarShaLeafs(cdc codec.BinaryCodec, bytes [][]byte, leafOps []*channeltypes.LeafOp) {
	for i, leaf := range bytes {
		err := leafOps[i].Unmarshal(leaf)
		if err != nil {
			panic(errors.New("failed to unmarshal leaf"))
		}
	}
}

// leafNumber 指明叶子结点位于哪一层
func verifyAggregateProof(
	ctx sdk.Context,
	cdc codec.BinaryCodec,
	leafNumber []uint64,
	values [][]byte,
	proofs [][]byte,
	root []byte,
	keyArr [][]byte,
	leafOps [][]byte) error {
	//首先解码，得到subproof
	ctx.Logger().Info("***********************************进入第五层验证函数***********************************")
	//var subProofs []*channeltypes.SubProof
	subProofs := make([]*channeltypes.SubProof, len(proofs))
	leafOpss := make([]*channeltypes.LeafOp, len(leafOps))
	for i := 0; i < len(proofs); i++ {
		subProofs[i] = &channeltypes.SubProof{}
	}
	for i := 0; i < len(leafOpss); i++ {
		leafOpss[i] = &channeltypes.LeafOp{}
	}
	unMarshaSubProof(cdc, proofs, subProofs)
	unMarShaLeafs(cdc, leafOps, leafOpss)
	ics23Leafs := make([]*ics23.LeafOp, len(leafOpss))
	for i := 0; i < len(ics23Leafs); i++ {
		ics23Leafs[i] = toIcs23(leafOpss[i])
	}
	values = calculateLeafs(values, ics23Leafs, keyArr)
	// 结合 leafNumber 检查values是否存在于subProofs
	subproofMap := make(map[uint64]*types.SubProof)
	for _, subProof := range subProofs {
		subproofMap[subProof.Number] = subProof
	}
	// 对SubProof原地排序
	sort.Slice(subProofs, func(i, j int) bool {
		return subProofs[i].Number > subProofs[j].Number
	})

	start := time.Now()
	for j, value := range values {
		subProof := subproofMap[leafNumber[j]]
		found := false
		if subProof != nil {
			for _, proofMeta := range subProof.ProofMetaList {
				meta1 := proofMeta.HashValue
				err, contains := checkInnerOpIsContainBytes(proofMeta.PathInnerOp, value)
				if err != nil {
					return err
				}
				if bytes.Equal(meta1, value) || contains {
					found = true
					break
				}
			}
			if !found {
				return errorsmod.Wrapf(ErrInvalidProofSpecs, "failed to find subproof for leaf")
			}
		}
	}

	for i := 0; i < len(subProofs)-2; i++ {
		currentProof := subProofs[i]
		nextProof := subProofs[i+1]
		for _, proofMeta := range currentProof.ProofMetaList {
			meta1 := proofMeta.HashValue
			if len(proofMeta.RealValue) != 0 {
				meta1 = proofMeta.RealValue
			}
			preimage := proofMeta.PathInnerOp.Prefix
			preimage = append(preimage, meta1...)
			preimage = append(preimage, proofMeta.PathInnerOp.Suffix...)
			combinedHash, err := doHash(HashOp_SHA256, preimage)
			if err != nil {
				return err
			}
			found := false
			for _, nextProofMeta := range nextProof.ProofMetaList {
				meta1_netxt := nextProofMeta.HashValue
				_, contains := checkInnerOpIsContainBytes(nextProofMeta.PathInnerOp, combinedHash)
				if bytes.Equal(combinedHash, meta1_netxt) || contains {
					found = true
					break
				}
			}
			if !found {
				return errorsmod.Wrapf(ErrInvalidProofSpecs, "failed to find subProof in nextnevel ")
			}
		}
	}

	//最后一层只有两个结点
	finalSubProof := subProofs[len(subProofs)-1].ProofMetaList
	for _, proofMeta := range finalSubProof {
		meta1 := proofMeta.HashValue
		preimage := proofMeta.PathInnerOp.Prefix
		preimage = append(preimage, meta1...)
		preimage = append(preimage, proofMeta.PathInnerOp.Suffix...)
		combinedHash, err := doHash(HashOp_SHA256, preimage)
		if err != nil {
			return err
		}
		if bytes.Equal(root, combinedHash) {
			elapsed1 := time.Since(start).Milliseconds()
			elapsed2 := time.Since(start).Microseconds()
			ctx.Logger().Info("***************************************Aggregate验证算法执行时间**************************************************", "ms", elapsed1, "us", elapsed2)
			return nil
		}
	}
	return errorsmod.Wrapf(ErrInvalidProofSpecs, "root hash calculated  not match the root given ")
}

// VerifyMembership is a generic proof verification method which verifies a proof of the existence of a value at a given CommitmentPath at the specified height.
// The caller is expected to construct the full CommitmentPath from a CommitmentPrefix and a standardized path (as defined in ICS 24).
// If a zero proof height is passed in, it will fail to retrieve the associated consensus state.
func (cs ClientState) VerifyMembership(
	ctx sdk.Context,
	clientStore storetypes.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	delayTimePeriod uint64,
	delayBlockPeriod uint64,
	proof []byte,
	path exported.Path,
	value []byte,
) error {
	if cs.GetLatestHeight().LT(height) {
		return errorsmod.Wrapf(
			ibcerrors.ErrInvalidHeight,
			"client state height < proof height (%d < %d), please ensure the client has been updated", cs.GetLatestHeight(), height,
		)
	}

	if err := verifyDelayPeriodPassed(ctx, clientStore, height, delayTimePeriod, delayBlockPeriod); err != nil {
		return err
	}

	var merkleProof commitmenttypes.MerkleProof
	if err := cdc.Unmarshal(proof, &merkleProof); err != nil {
		return errorsmod.Wrap(commitmenttypes.ErrInvalidProof, "failed to unmarshal proof into ICS 23 commitment merkle proof")
	}

	merklePath, ok := path.(commitmenttypes.MerklePath)
	if !ok {
		return errorsmod.Wrapf(ibcerrors.ErrInvalidType, "expected %T, got %T", commitmenttypes.MerklePath{}, path)
	}

	consensusState, found := GetConsensusState(clientStore, cdc, height)
	if !found {
		return errorsmod.Wrap(clienttypes.ErrConsensusStateNotFound, "please ensure the proof was constructed against a height that exists on the client")
	}

	return merkleProof.VerifyMembership(cs.ProofSpecs, consensusState.GetRoot(), merklePath, value)
}

// VerifyNonMembership is a generic proof verification method which verifies the absence of a given CommitmentPath at a specified height.
// The caller is expected to construct the full CommitmentPath from a CommitmentPrefix and a standardized path (as defined in ICS 24).
// If a zero proof height is passed in, it will fail to retrieve the associated consensus state.
func (cs ClientState) VerifyNonMembership(
	ctx sdk.Context,
	clientStore storetypes.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	delayTimePeriod uint64,
	delayBlockPeriod uint64,
	proof []byte,
	path exported.Path,
) error {
	if cs.GetLatestHeight().LT(height) {
		return errorsmod.Wrapf(
			ibcerrors.ErrInvalidHeight,
			"client state height < proof height (%d < %d), please ensure the client has been updated", cs.GetLatestHeight(), height,
		)
	}

	if err := verifyDelayPeriodPassed(ctx, clientStore, height, delayTimePeriod, delayBlockPeriod); err != nil {
		return err
	}

	var merkleProof commitmenttypes.MerkleProof
	if err := cdc.Unmarshal(proof, &merkleProof); err != nil {
		return errorsmod.Wrap(commitmenttypes.ErrInvalidProof, "failed to unmarshal proof into ICS 23 commitment merkle proof")
	}

	merklePath, ok := path.(commitmenttypes.MerklePath)
	if !ok {
		return errorsmod.Wrapf(ibcerrors.ErrInvalidType, "expected %T, got %T", commitmenttypes.MerklePath{}, path)
	}

	consensusState, found := GetConsensusState(clientStore, cdc, height)
	if !found {
		return errorsmod.Wrap(clienttypes.ErrConsensusStateNotFound, "please ensure the proof was constructed against a height that exists on the client")
	}

	return merkleProof.VerifyNonMembership(cs.ProofSpecs, consensusState.GetRoot(), merklePath)
}

// verifyDelayPeriodPassed will ensure that at least delayTimePeriod amount of time and delayBlockPeriod number of blocks have passed
// since consensus state was submitted before allowing verification to continue.
func verifyDelayPeriodPassed(ctx sdk.Context, store storetypes.KVStore, proofHeight exported.Height, delayTimePeriod, delayBlockPeriod uint64) error {
	if delayTimePeriod != 0 {
		// check that executing chain's timestamp has passed consensusState's processed time + delay time period
		processedTime, ok := GetProcessedTime(store, proofHeight)
		if !ok {
			return errorsmod.Wrapf(ErrProcessedTimeNotFound, "processed time not found for height: %s", proofHeight)
		}

		currentTimestamp := uint64(ctx.BlockTime().UnixNano())
		validTime := processedTime + delayTimePeriod

		// NOTE: delay time period is inclusive, so if currentTimestamp is validTime, then we return no error
		if currentTimestamp < validTime {
			return errorsmod.Wrapf(ErrDelayPeriodNotPassed, "cannot verify packet until time: %d, current time: %d",
				validTime, currentTimestamp)
		}

	}

	if delayBlockPeriod != 0 {
		// check that executing chain's height has passed consensusState's processed height + delay block period
		processedHeight, ok := GetProcessedHeight(store, proofHeight)
		if !ok {
			return errorsmod.Wrapf(ErrProcessedHeightNotFound, "processed height not found for height: %s", proofHeight)
		}

		currentHeight := clienttypes.GetSelfHeight(ctx)
		validHeight := clienttypes.NewHeight(processedHeight.GetRevisionNumber(), processedHeight.GetRevisionHeight()+delayBlockPeriod)

		// NOTE: delay block period is inclusive, so if currentHeight is validHeight, then we return no error
		if currentHeight.LT(validHeight) {
			return errorsmod.Wrapf(ErrDelayPeriodNotPassed, "cannot verify packet until height: %s, current height: %s",
				validHeight, currentHeight)
		}
	}

	return nil
}
