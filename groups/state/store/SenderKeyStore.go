package store

import (
	"github.com/Luca3317/libsignalcopy/groups/state/record"
	"github.com/Luca3317/libsignalcopy/protocol"
)

type SenderKey interface {
	StoreSenderKey(senderKeyName *protocol.SenderKeyName, keyRecord *record.SenderKey)
	LoadSenderKey(senderKeyName *protocol.SenderKeyName) *record.SenderKey
}
