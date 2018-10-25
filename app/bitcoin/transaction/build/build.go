package build

import (
	"sort"

	"github.com/jchavannes/btcd/wire"
	"github.com/jchavannes/jgo/jerr"
	"github.com/memocash/memo/app/bitcoin/memo"
	"github.com/memocash/memo/app/bitcoin/transaction"
	"github.com/memocash/memo/app/bitcoin/wallet"
	"github.com/memocash/memo/app/db"
)

const notEnoughValueErrorText = "unable to find enough value to spend"

var notEnoughValueError = jerr.New(notEnoughValueErrorText)

func IsNotEnoughValueError(err error) bool {
	return jerr.HasError(err, notEnoughValueErrorText)
}

func Build(outputs []memo.Output, privateKey *wallet.PrivateKey) (*memo.Tx, error) {
	spendableTxOuts, err := db.GetSpendableTransactionOutputsForPkHash(privateKey.GetPublicKey().GetAddress().GetScriptAddress())
	if err != nil {
		return nil, jerr.Get("error getting spendable tx outs", err)
	}
	sort.Sort(db.TxOutSortByValue(spendableTxOuts))
	memoTx, _, err := buildWithTxOuts(outputs, spendableTxOuts, privateKey)
	if err != nil {
		return nil, jerr.Get("error creating tx", err)
	}
	return memoTx, nil
}

func buildWithTxOuts(outputs []memo.Output, spendableTxOuts []*db.TransactionOut, privateKey *wallet.PrivateKey) (*memo.Tx, []*db.TransactionOut, error) {
	var minInput = int64(memo.BaseTxFee + memo.InputFeeP2PKH + memo.OutputFeeP2PKH + memo.DustMinimumOutput)

	var spendOutputType memo.OutputType
	for _, spendOutput := range outputs {
		switch spendOutput.Type {
		case memo.OutputTypeP2PK:
			minInput += memo.OutputFeeP2PKH + spendOutput.Amount
		default:
			spendOutputType = spendOutput.Type
			outputFee, err := getMemoOutputFee(spendOutput)
			if err != nil {
				return nil, nil, jerr.Get("error getting memo output fee", err)
			}
			minInput += outputFee
		}
	}

	var txOutsToUse []*db.TransactionOut
	var totalInputValue int64
	for {
		if len(spendableTxOuts) == 0 {
			return nil, nil, notEnoughValueError
		}
		spendableTxOut := spendableTxOuts[0]
		spendableTxOuts = spendableTxOuts[1:]
		txOutsToUse = append(txOutsToUse, spendableTxOut)
		totalInputValue += spendableTxOut.Value
		if totalInputValue > minInput {
			break
		}
		minInput += memo.InputFeeP2PKH
	}

	var fee = int64(memo.BaseTxFee+len(txOutsToUse)*memo.InputFeeP2PKH) + memo.OutputFeeP2PKH

	var totalOutputValue int64
	for _, spendOutput := range outputs {
		totalOutputValue += spendOutput.Amount
		switch spendOutput.Type {
		case memo.OutputTypeP2PK:
			fee += memo.OutputFeeP2PKH
		default:
			outputFee, err := getMemoOutputFee(spendOutput)
			if err != nil {
				return nil, nil, jerr.Get("error getting memo output fee", err)
			}
			fee += outputFee
		}
	}

	var change = totalInputValue - fee - totalOutputValue
	if change < memo.DustMinimumOutput {
		return nil, nil, jerr.New("change value below dust minimum input")
	}
	address := privateKey.GetPublicKey().GetAddress()
	outputs = append([]memo.Output{{
		Type:    memo.OutputTypeP2PK,
		Address: address,
		Amount:  change,
	}}, outputs...)

	var tx *wire.MsgTx
	tx, err := transaction.Create(txOutsToUse, privateKey, outputs)
	if err != nil {
		return nil, nil, jerr.Get("error creating tx", err)
	}
	var inputs []*memo.TxInput
	for _, txOut := range txOutsToUse {
		inputs = append(inputs, &memo.TxInput{
			PkHash:      txOut.KeyPkHash,
			Value:       txOut.Value,
			PrevOutHash: txOut.GetHashString(),
		})
	}
	txHash := tx.TxHash()
	var index uint32 = 0
	spendableTxOuts = append([]*db.TransactionOut{{
		TransactionHash: txHash.CloneBytes(),
		PkScript:        tx.TxOut[index].PkScript,
		Index:           index,
		Value:           change,
	}}, spendableTxOuts...)
	return &memo.Tx{
		SelfPkHash: address.GetScriptAddress(),
		Type:       spendOutputType,
		MsgTx:      tx,
		Inputs:     inputs,
	}, spendableTxOuts, nil
}

func getMemoOutputFee(output memo.Output) (int64, error) {
	switch output.Type {
	case memo.OutputTypeMemoMessage,
		memo.OutputTypeMemoLike,
		memo.OutputTypeMemoSetName,
		memo.OutputTypeMemoSetProfile,
		memo.OutputTypeMemoSetProfilePic,
		memo.OutputTypeMemoFollow, memo.OutputTypeMemoUnfollow,
		memo.OutputTypeMemoTopicFollow, memo.OutputTypeMemoTopicUnfollow:
		return int64(memo.OutputFeeOpReturn + len(output.Data)), nil
	case memo.OutputTypeMemoReply,
		memo.OutputTypeMemoTopicMessage,
		memo.OutputTypeMemoPollOption,
		memo.OutputTypeMemoPrivateMessage,
		memo.OutputTypeMemoPollVote:
		return int64(memo.OutputFeeOpReturn + len(output.Data) + memo.OutputOpDataFee + len(output.RefData)), nil
	case memo.OutputTypeMemoPollQuestionSingle,
		memo.OutputTypeMemoPollQuestionMulti:
		return int64(memo.OutputFeeOpReturn + (memo.OutputOpDataFee+1)*2 + len(output.Data)), nil
	}
	return 0, jerr.New("unable to get fee for output type")
}
