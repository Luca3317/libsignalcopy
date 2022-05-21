package retrievable

// TODO
// CreateBundle/ReadBundle
// maybe marshaled25519 instead of the generic marshalling

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"

	"github.com/Luca3317/libsignalcopy/ecc"
	"github.com/Luca3317/libsignalcopy/keys/identity"
	"github.com/Luca3317/libsignalcopy/serialize"
	"github.com/Luca3317/libsignalcopy/state/record"
	"github.com/Luca3317/libsignalcopy/util/keyhelper"
	"github.com/libp2p/go-libp2p-core/crypto"
)

const idspath = "ids.bin"
const prekeypath = "prekey.bin"
const sigprekeypath = "sigprekey.bin"

const idkeypairpath = "idkeypair.bin"
const idkeypubpath = "idkeypub.bin"
const idkeyprivpath = "idkeypriv.bin"

type IDs struct {
	RegID uint32
	DevID uint32
}

func writefile(content []byte, path string) {

	permissions := 0644
	err := ioutil.WriteFile(path, content, fs.FileMode(permissions))

	if err != nil {
		log.Fatalf("FAILED TO WRITE TO FILE %v", path)
		os.Remove(path)
	}
}

func readfile(content *[]byte, path string) {

	var err error
	*content, err = ioutil.ReadFile(path)

	if err != nil {
		log.Fatalf("FAILED TO READ FROM FILE %v", path)
		*content = nil
	}
}

func IDsToGOB(id IDs) []byte {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	err := e.Encode(id)
	if err != nil {
		log.Fatal("failed gob encode ids")
	}

	return b.Bytes()
}

func IDsFromGOB(by []byte) IDs {
	i := IDs{}
	b := bytes.Buffer{}
	b.Write(by)
	d := gob.NewDecoder(&b)
	err := d.Decode(&i)
	if err != nil {
		fmt.Println("failed gob decode ids")
	}

	return i
}

func InitGOB() {
	gob.Register(IDs{})
}

type RetrievableRaw struct {
	Ids                 IDs
	PreKey              []byte
	SignedPreKey        []byte
	IdentityKeyPairPub  []byte
	IdentityKeyPairPriv []byte
}

type Retrievable struct {
	Ids                 IDs
	PreKey              record.PreKey
	SignedPreKey        record.SignedPreKey
	IdentityKeyPairPub  crypto.PubKey
	IdentityKeyPairPriv crypto.PrivKey
}

// TODO dont hardcode devid
func CreateIDs() IDs {
	ids := IDs{
		RegID: keyhelper.GenerateRegistrationID(),
		DevID: 12,
	}

	idBytes := IDsToGOB(ids)
	writefile(idBytes, idspath)
	return ids
}

func CreatePreKey() []byte {
	preKeys, err := keyhelper.GeneratePreKeys(0, 10, serialize.NewJSONSerializer().PreKeyRecord)
	if err != nil {
		log.Fatal("failed to generate prekeys")
	}

	preKeyBytes := preKeys[0].Serialize()
	writefile(preKeyBytes, prekeypath)
	return preKeyBytes
}

func CreateSignedPreKey(idKeyPair *identity.KeyPair) []byte {
	signedPreKey, err := keyhelper.GenerateSignedPreKey(idKeyPair, 0, serialize.NewJSONSerializer().SignedPreKeyRecord)
	if err != nil {
		log.Fatal("failed to generate pre keys")
	}

	signedPreKeyBytes := signedPreKey.Serialize()
	writefile(signedPreKeyBytes, sigprekeypath)
	return signedPreKeyBytes
}

func CreateBundle(pubLibp2p crypto.PubKey, privLibp2p crypto.PrivKey) RetrievableRaw {
	pub, priv := SaveIDKeyPair(pubLibp2p, privLibp2p)
	return RetrievableRaw{
		Ids:                 CreateIDs(),
		PreKey:              CreatePreKey(),
		IdentityKeyPairPub:  pub,
		IdentityKeyPairPriv: priv,
		SignedPreKey:        CreateSignedPreKey(ConvertIDKeysLibp2pToSig(pubLibp2p, privLibp2p)),
	}
}

// ID keypairs are handled differently; The go implementations are saved / read
// To get Signal compatible, equivalent keys, use ConvertIDKeysLibp2pToSig
func SaveIDKeyPair(pubLibp2p crypto.PubKey, privLibp2p crypto.PrivKey) (pubBytes []byte, privBytes []byte) {
	pubBytes, err := crypto.MarshalPublicKey(pubLibp2p)
	privBytes, err2 := crypto.MarshalPrivateKey(privLibp2p)
	if err != nil {
		panic(err)
	} else if err2 != nil {
		panic(err2)
	}

	writefile(pubBytes, idkeypubpath)
	writefile(privBytes, idkeyprivpath)
	return pubBytes, privBytes
}

func ReadIDs() IDs {
	if _, err := os.Stat(idspath); err != nil {
		panic(err)
	}

	var idBytes []byte
	readfile(&idBytes, idspath)
	return IDsFromGOB(idBytes)
}

func ReadPreKey() []byte {
	if _, err := os.Stat(prekeypath); err != nil {
		panic(err)
	}

	var preKeyBytes []byte
	readfile(&preKeyBytes, prekeypath)
	return preKeyBytes
}

func ReadSignedPreKey() []byte {
	if _, err := os.Stat(sigprekeypath); err != nil {
		panic(err)
	}

	var sigPreKeyBytes []byte
	readfile(&sigPreKeyBytes, sigprekeypath)
	return sigPreKeyBytes
}

// Returns a marshalled public and private key, if one is saved on file
// ID keypairs are handled differently; The go implementations are saved / read
// To get Signal compatible equivalent keys, use ConvertIDKeysLibp2pToSig
func ReadIDKeyPair() (pubBytes []byte, privBytes []byte) {
	if _, err := os.Stat(idkeypubpath); err != nil {
		panic(err)
	} else if _, err = os.Stat(idkeyprivpath); err != nil {
		panic(err)
	}

	readfile(&pubBytes, idkeypubpath)
	readfile(&privBytes, idkeyprivpath)

	return pubBytes, privBytes
}

func ReadBundle() RetrievableRaw {
	pub, priv := ReadIDKeyPair()

	return RetrievableRaw{
		Ids:                 ReadIDs(),
		PreKey:              ReadPreKey(),
		IdentityKeyPairPub:  pub,
		IdentityKeyPairPriv: priv,
		SignedPreKey:        ReadSignedPreKey(),
	}
}

func ConvertIDKeysLibp2pToSig(pubLibp2p crypto.PubKey, privLibp2p crypto.PrivKey) *identity.KeyPair {

	idKeyPair := &identity.KeyPair{}

	// Turn pubLibp2p key into signal compatible public key (identity.key)
	var pubSignal identity.Key
	pubLibp2pBytes, err := pubLibp2p.Raw()
	if err != nil {
		log.Fatal("failed to get raw bytes from publibp2p")
	}

	var pubLibp2pBytesFix [32]byte
	copy(pubLibp2pBytesFix[:], pubLibp2pBytes)
	pubSignal = identity.NewKeyFromBytes(pubLibp2pBytesFix, 0)

	// Turn privLibp2p key into signal compatible private key (ecc.ECPrivateKeyable)
	var privSignal ecc.ECPrivateKeyable
	privLibp2pBytes, err := privLibp2p.Raw()
	if err != nil {
		log.Fatal("failed to get raw bytes from privlibp2p")
	}

	var privLibp2pBytesFix [32]byte
	copy(privLibp2pBytesFix[:], privLibp2pBytes)
	privSignal = ecc.NewDjbECPrivateKey(privLibp2pBytesFix)

	idKeyPair = identity.NewKeyPair(&pubSignal, privSignal)
	return idKeyPair
}
