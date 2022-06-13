package serialize

import (
	"lib/libsignalcopy/util/bytehelper"
	"strconv"

	"github.com/Luca3317/libsignalcopy/logger"
	"github.com/Luca3317/libsignalcopy/protocol"
	proto "github.com/golang/protobuf/proto"
)

// NewProtoBufSerializer will return a serializer for all Signal objects that will
// be responsible for converting objects to and from ProtoBuf bytes.
func NewProtoBufSerializer() *Serializer {
	serializer := NewSerializer()

	serializer.SignalMessage = &ProtoBufSignalMessageSerializer{}
	serializer.PreKeySignalMessage = &ProtoBufPreKeySignalMessageSerializer{}
	serializer.SenderKeyMessage = &ProtoBufSenderKeyMessageSerializer{}
	serializer.SenderKeyDistributionMessage = &ProtoBufSenderKeyDistributionMessageSerializer{}
	serializer.SignedPreKeyRecord = &JSONSignedPreKeyRecordSerializer{}
	serializer.PreKeyRecord = &JSONPreKeyRecordSerializer{}
	serializer.State = &JSONStateSerializer{}
	serializer.Session = &JSONSessionSerializer{}
	serializer.SenderKeyRecord = &JSONSenderKeySessionSerializer{}
	serializer.SenderKeyState = &JSONSenderKeyStateSerializer{}

	return serializer
}

func highBitsToInt(value byte) int {
	return int((value & 0xFF) >> 4)
}

func intsToByteHighAndLow(highValue, lowValue int) byte {
	return byte((highValue<<4 | lowValue) & 0xFF)
}

// ProtoBufSignalMessageSerializer is a structure for serializing signal messages into
// and from ProtoBuf.
type ProtoBufSignalMessageSerializer struct{}

// Serialize will take a signal message structure and convert it to ProtoBuf bytes.
func (j *ProtoBufSignalMessageSerializer) Serialize(signalMessage *protocol.SignalMessageStructure) []byte {

	sm := &SignalMessage{
		RatchetKey:      signalMessage.RatchetKey,
		Counter:         &signalMessage.Counter,
		PreviousCounter: &signalMessage.PreviousCounter,
		Ciphertext:      signalMessage.CipherText,
	}
	var serialized []byte
	message, err := proto.Marshal(sm)
	if err != nil {
		logger.Error("Error serializing signal message: ", err)
	}

	if signalMessage.Version != 0 {
		serialized = append(serialized, []byte(strconv.Itoa(signalMessage.Version))...)
	}
	serialized = append(serialized, message...)

	if signalMessage.Mac != nil {
		serialized = append(serialized, signalMessage.Mac...)
	}

	return serialized
}

// Deserialize will take in ProtoBuf bytes and return a signal message structure.
func (j *ProtoBufSignalMessageSerializer) Deserialize(serialized []byte) (*protocol.SignalMessageStructure, error) {
	parts, err := bytehelper.SplitThree(serialized, 1, len(serialized)-1-protocol.MacLength, protocol.MacLength)
	if err != nil {
		logger.Error("Error split signal message: ", err)
		return nil, err
	}
	version := highBitsToInt(parts[0][0])
	message := parts[1]
	mac := parts[2]

	var sm SignalMessage
	err = proto.Unmarshal(message, &sm)
	if err != nil {
		logger.Error("Error deserializing signal message: ", err)
		return nil, err
	}

	signalMessage := protocol.SignalMessageStructure{
		Version:         version,
		RatchetKey:      sm.GetRatchetKey(),
		Counter:         sm.GetCounter(),
		PreviousCounter: sm.GetPreviousCounter(),
		CipherText:      sm.GetCiphertext(),
		Mac:             mac,
	}

	return &signalMessage, nil
}
