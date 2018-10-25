package transaction

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/jchavannes/btcd/txscript"
	"github.com/jchavannes/btcd/wire"
	"github.com/jchavannes/jgo/jerr"
	"github.com/memocash/memo/app/bitcoin/memo"
	"github.com/memocash/memo/app/bitcoin/wallet"
	"github.com/memocash/memo/app/db"
)

func Create(spendOuts []*db.TransactionOut, privateKey *wallet.PrivateKey, spendOutputs []memo.Output) (*wire.MsgTx, error) {
	var txOuts []*wire.TxOut
	for _, spendOutput := range spendOutputs {
		switch spendOutput.Type {
		case memo.OutputTypeP2PK:
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_DUP).
				AddOp(txscript.OP_HASH160).
				AddData(spendOutput.Address.GetScriptAddress()).
				AddOp(txscript.OP_EQUALVERIFY).
				AddOp(txscript.OP_CHECKSIG).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating pay to addr output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeReturn:
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData(spendOutput.Data).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating op return output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(0, pkScript))
		case memo.OutputTypeMemoMessage:
			if len(spendOutput.Data) > memo.MaxPostSize {
				return nil, jerr.New("message size too large")
			}
			if len(spendOutput.Data) == 0 {
				return nil, jerr.New("empty message")
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodePost}).
				AddData(spendOutput.Data).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo message output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeMemoSetName:
			if len(spendOutput.Data) > memo.MaxPostSize {
				return nil, jerr.New("name too large")
			}
			if len(spendOutput.Data) == 0 {
				return nil, jerr.New("empty name")
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodeSetName}).
				AddData(spendOutput.Data).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo set name output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeMemoFollow:
			if len(spendOutput.Data) > memo.MaxPostSize {
				return nil, jerr.New("data too large")
			}
			if len(spendOutput.Data) == 0 {
				return nil, jerr.New("empty data")
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodeFollow}).
				AddData(spendOutput.Data).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo follow output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeMemoUnfollow:
			if len(spendOutput.Data) > memo.MaxPostSize {
				return nil, jerr.New("data too large")
			}
			if len(spendOutput.Data) == 0 {
				return nil, jerr.New("empty data")
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodeUnfollow}).
				AddData(spendOutput.Data).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo unfollow output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeMemoLike:
			if len(spendOutput.Data) > memo.MaxPostSize {
				return nil, jerr.New("data too large")
			}
			if len(spendOutput.Data) == 0 {
				return nil, jerr.New("empty data")
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodeLike}).
				AddData(spendOutput.Data).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo like output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeMemoReply:
			if len(spendOutput.Data) > memo.MaxReplySize {
				return nil, jerr.New("data too large")
			}
			if len(spendOutput.Data) == 0 {
				return nil, jerr.New("empty data")
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodeReply}).
				AddData(spendOutput.RefData).
				AddData(spendOutput.Data).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo reply output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeMemoSetProfile:
			if len(spendOutput.Data) > memo.MaxPostSize {
				return nil, jerr.New("profile too large")
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodeSetProfile}).
				AddData(spendOutput.Data).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo set profile output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeMemoTopicMessage:
			if len(spendOutput.Data)+len(spendOutput.RefData) > memo.MaxTagMessageSize {
				return nil, jerr.New("data too large")
			}
			if len(spendOutput.Data) == 0 || len(spendOutput.RefData) == 0 {
				return nil, jerr.New("empty data")
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodeTopicMessage}).
				AddData(spendOutput.RefData).
				AddData(spendOutput.Data).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo tag message output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeMemoTopicFollow:
			if len(spendOutput.Data) > memo.MaxTagMessageSize {
				return nil, jerr.New("data too large")
			}
			if len(spendOutput.Data) == 0 {
				return nil, jerr.New("empty data")
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodeTopicFollow}).
				AddData(spendOutput.Data).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo topic follow output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeMemoTopicUnfollow:
			if len(spendOutput.Data) > memo.MaxTagMessageSize {
				return nil, jerr.New("data too large")
			}
			if len(spendOutput.Data) == 0 {
				return nil, jerr.New("empty data")
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodeTopicUnfollow}).
				AddData(spendOutput.Data).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo topic unfollow output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeMemoPollQuestionSingle, memo.OutputTypeMemoPollQuestionMulti:
			var question = spendOutput.Data
			var optionCount = spendOutput.RefData
			if len(question) > memo.MaxPollQuestionSize {
				return nil, jerr.New("question size too large")
			}
			if len(question) == 0 {
				return nil, jerr.New("empty question")
			}
			if len(optionCount) == 0 {
				return nil, jerr.New("empty option count")
			}
			var pollType byte
			switch spendOutput.Type {
			case memo.OutputTypeMemoPollQuestionSingle:
				pollType = memo.CodePollTypeSingle
			case memo.OutputTypeMemoPollQuestionMulti:
				pollType = memo.CodePollTypeMulti
			default:
				return nil, jerr.New("invalid poll type")
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodePollCreate}).
				AddData([]byte{pollType}).
				AddData(optionCount).
				AddData(question).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo question output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeMemoPollOption:
			var option = spendOutput.Data
			var parentTxHash = spendOutput.RefData
			if len(option) > memo.MaxPollOptionSize {
				return nil, jerr.New("option size too large")
			}
			if len(option) == 0 {
				return nil, jerr.New("empty option")
			}
			if len(parentTxHash) != 32 {
				return nil, jerr.Newf("parent tx hash length incorrect (expected 32, got: %d)", len(parentTxHash))
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodePollOption}).
				AddData(parentTxHash).
				AddData(option).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo option output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeMemoPollVote:
			if len(spendOutput.Data) != 32 {
				return nil, jerr.New("invalid txn hash")
			}
			if len(spendOutput.RefData) > memo.MaxVoteCommentSize {
				return nil, jerr.New("comment data too large")
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodePollVote}).
				AddData(spendOutput.Data).
				AddData(spendOutput.RefData).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo poll vote output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeMemoPrivateMessage:
			if len(spendOutput.Data)+len(spendOutput.RefData) > memo.MaxPostSize {
				return nil, jerr.New("message size too large")
			}
			if len(spendOutput.Data) == 0 {
				return nil, jerr.New("empty message")
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodePrivateMessage}).
				AddData(spendOutput.Data).
				AddData(spendOutput.RefData).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo private message output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		case memo.OutputTypeMemoSetProfilePic:
			if len(spendOutput.Data) > memo.MaxPostSize {
				return nil, jerr.New("url too large")
			}
			if len(spendOutput.Data) == 0 {
				return nil, jerr.New("empty url")
			}
			pkScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_RETURN).
				AddData([]byte{memo.CodePrefix, memo.CodeSetProfilePicture}).
				AddData(spendOutput.Data).
				Script()
			if err != nil {
				return nil, jerr.Get("error creating memo set pic output", err)
			}
			txOuts = append(txOuts, wire.NewTxOut(spendOutput.Amount, pkScript))
		}
	}

	var txIns []*wire.TxIn
	var totalValue int64
	for _, spendOut := range spendOuts {
		hash, err := chainhash.NewHash(spendOut.TransactionHash)
		if err != nil {
			return nil, jerr.Get("error getting transaction hash", err)
		}
		newTxIn := wire.NewTxIn(&wire.OutPoint{
			Hash:  *hash,
			Index: uint32(spendOut.Index),
		}, nil)
		txIns = append(txIns, newTxIn)
		totalValue += spendOut.Value
	}

	var tx = &wire.MsgTx{
		Version:  wire.TxVersion,
		TxIn:     txIns,
		TxOut:    txOuts,
		LockTime: 0,
	}

	for i := 0; i < len(spendOuts); i++ {
		signature, err := txscript.SignatureScript(
			tx,
			i,
			spendOuts[i].PkScript,
			txscript.SigHashAll+wallet.SigHashForkID,
			privateKey.GetBtcEcPrivateKey(),
			true,
			spendOuts[i].Value,
		)
		if err != nil {
			return nil, jerr.Get("error signing transaction", err)
		}
		txIns[i].SignatureScript = signature
	}
	return tx, nil
}
