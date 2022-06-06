package retrievable

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
	"github.com/Luca3317/libsignalcopy/util/bytehelper"
	"github.com/Luca3317/libsignalcopy/util/keyhelper"
	"github.com/libp2p/go-libp2p-core/crypto"
)

const idspath = "ids.bin"
const prekeypath = "prekey.bin"
const sigprekeypath = "sigprekey.bin"

const idkeypairpath = "idkeypair.bin"
const idkeypubpath = "idkeypub.bin"
const idkeyprivpath = "idkeypriv.bin"

const libp2pkeypubpath = "libp2pkeypub.bin"
const libp2pkeyprivpath = "libp2pkeypriv.bin"

type IDs struct {
	RegID uint32
	DevID uint32
}

type RetrievableRaw struct {
	Ids                 IDs
	PreKey              []byte
	SignedPreKey        []byte
	IdentityKeyPairPub  []byte
	IdentityKeyPairPriv []byte
}

type Retrievable struct {
	Ids             IDs
	PreKey          record.PreKey
	SignedPreKey    record.SignedPreKey
	IdentityKeyPair identity.KeyPair
}

func Writefile(content []byte, path string) error {

	permissions := 0644
	err := ioutil.WriteFile(path, content, fs.FileMode(permissions))

	if err != nil {
		os.Remove(path)
		return err
	}

	return nil
}

func Readfile(content *[]byte, path string) error {

	var err error
	*content, err = ioutil.ReadFile(path)

	if err != nil {
		*content = nil
		return err
	}

	return nil
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

func CreateIDs() IDs {
	ids := IDs{
		RegID: keyhelper.GenerateRegistrationID(),
		DevID: 12,
	}

	idBytes := IDsToGOB(ids)
	Writefile(idBytes, idspath)
	return ids
}

func ReadIDs() IDs {
	if _, err := os.Stat(idspath); err != nil {
		panic(err)
	}

	var idBytes []byte
	Readfile(&idBytes, idspath)
	return IDsFromGOB(idBytes)
}

func CreatePreKey() ([]byte, error) {
	prekeys, err := keyhelper.GeneratePreKeys(0, 1, serialize.NewJSONSerializer().PreKeyRecord)
	if err != nil {
		return nil, err
	}

	prekey := prekeys[0].Serialize()
	err = Writefile(prekey, prekeypath)
	if err != nil {
		return nil, err
	}

	return prekey, nil
}

func ReadPreKey() ([]byte, error) {
	var prekey []byte
	if err := Readfile(&prekey, prekeypath); err != nil {
		return nil, err
	}

	return prekey, nil
}

func CreateSignedPreKey(idkeypair identity.KeyPair) ([]byte, error) {
	signedprekey, err := keyhelper.GenerateSignedPreKey(&idkeypair, 0, serialize.NewJSONSerializer().SignedPreKeyRecord)
	if err != nil {
		return nil, err
	}

	signedprekeybytes := signedprekey.Serialize()
	err = Writefile(signedprekeybytes, sigprekeypath)
	if err != nil {
		return nil, err
	}

	return signedprekeybytes, nil
}

func ReadSignedPreKey() ([]byte, error) {
	var signedprekey []byte
	if err := Readfile(&signedprekey, sigprekeypath); err != nil {
		return nil, err
	}

	return signedprekey, nil
}

func CreateIdentityKeyPair() (pub []byte, priv []byte, err error) {
	idkeypair, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		return nil, nil, err
	}

	pub = idkeypair.PublicKey().Serialize()
	priv = bytehelper.ArrayToSlice(idkeypair.PrivateKey().Serialize())

	if err = Writefile(pub, idkeypubpath); err != nil {
		return nil, nil, err
	}
	if err = Writefile(priv, idkeyprivpath); err != nil {
		return nil, nil, err
	}

	return pub, priv, err
}

func ReadIdentityKeyPair() (pub []byte, priv []byte, err error) {
	if err = Readfile(&pub, idkeypubpath); err != nil {
		return nil, nil, err
	}

	if err = Readfile(&priv, idkeyprivpath); err != nil {
		return nil, nil, err
	}

	return pub, priv, nil
}

func ReadIdentityKeyPair2() identity.KeyPair {
	var pub, priv []byte
	Readfile(&pub, idkeypubpath)
	Readfile(&priv, idkeyprivpath)

	var readpubfix, readprivfix [32]byte
	copy(readpubfix[:], pub[1:])
	copy(readprivfix[:], priv)

	retpub := identity.NewKeyFromBytes(readpubfix, 0)
	retpriv := ecc.NewDjbECPrivateKey(readprivfix)
	return *identity.NewKeyPair(&retpub, retpriv)
}

func CreateBundleRaw() (RetrievableRaw, error) {
	ids := CreateIDs()

	prekey, err := CreatePreKey()
	if err != nil {
		return RetrievableRaw{}, err
	}

	pub, priv, err := CreateIdentityKeyPair()
	if err != nil {
		return RetrievableRaw{}, err
	}

	idkeypair := ReadIdentityKeyPair2()
	signedprekey, err := CreateSignedPreKey(idkeypair)
	if err != nil {
		return RetrievableRaw{}, err
	}

	return RetrievableRaw{
		Ids:                 ids,
		PreKey:              prekey,
		SignedPreKey:        signedprekey,
		IdentityKeyPairPub:  pub,
		IdentityKeyPairPriv: priv,
	}, nil
}

func ReadBundleRaw() (RetrievableRaw, error) {
	ids := ReadIDs()

	prekey, err := ReadPreKey()
	if err != nil {
		return RetrievableRaw{}, err
	}

	pub, priv, err := ReadIdentityKeyPair()
	if err != nil {
		return RetrievableRaw{}, err
	}

	signedprekey, err := ReadSignedPreKey()
	if err != nil {
		return RetrievableRaw{}, err
	}

	return RetrievableRaw{
		Ids:                 ids,
		PreKey:              prekey,
		SignedPreKey:        signedprekey,
		IdentityKeyPairPub:  pub,
		IdentityKeyPairPriv: priv,
	}, nil
}

func ReadBundle() (Retrievable, error) {
	ids := ReadIDs()

	prekeybytes, err := ReadPreKey()
	if err != nil {
		return Retrievable{}, err
	}
	prekey, err := record.NewPreKeyFromBytes(prekeybytes, serialize.NewJSONSerializer().PreKeyRecord)
	if err != nil {
		return Retrievable{}, err
	}

	idkeypair := ReadIdentityKeyPair2()
	if err != nil {
		return Retrievable{}, err
	}

	signedprekeybytes, err := ReadSignedPreKey()
	if err != nil {
		return Retrievable{}, err
	}
	signedprekey, err := record.NewSignedPreKeyFromBytes(signedprekeybytes, serialize.NewJSONSerializer().SignedPreKeyRecord)
	if err != nil {
		return Retrievable{}, err
	}

	return Retrievable{
		Ids:             ids,
		PreKey:          *prekey,
		SignedPreKey:    *signedprekey,
		IdentityKeyPair: idkeypair,
	}, nil
}

/* func SaveLibP2PKeys(pub crypto.PubKey, priv crypto.PrivKey) (pubBytes []byte, privBytes []byte, err error) {
	pubBytes, err = crypto.MarshalPublicKey(pub)
	if err != nil {
		log.Fatal("Failed to marshal public key")
		return nil, nil, err
	}

	privBytes, err = crypto.MarshalPrivateKey(priv)
	if err != nil {
		log.Fatal("Failed to marshal private key")
		return nil, nil, err
	}

	err = writefile(pubBytes, libp2pkeypubpath)
	if err != nil {
		log.Fatal("Failed to write pubkey")
		return nil, nil, err
	}

	err = writefile(privBytes, libp2pkeyprivpath)
	if err != nil {
		log.Fatal("Failed to write privkey")
		return nil, nil, err
	}

	return pubBytes, privBytes, nil
}

func ReadLibP2PKeys() (pub []byte, priv []byte, err error) {
	err = readfile(&pub, libp2pkeypubpath)
	if err != nil {
		log.Fatal("Failed to read pubkey")
		return nil, nil, err
	}

	err = readfile(&priv, libp2pkeyprivpath)
	if err != nil {
		log.Fatal("Failed to write privkey")
		return nil, nil, err
	}

	return pub, priv, nil
} */
func SaveLibP2PKey(pub crypto.PubKey) ([]byte, error) {
	pubBytes, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		log.Fatal("Failed to marshal public key")
		return nil, err
	}

	err = Writefile(pubBytes, libp2pkeypubpath)
	if err != nil {
		log.Fatal("Failed to write pubkey")
		return nil, err
	}

	return pubBytes, nil
}

func ReadLibP2PKeys() ([]byte, error) {
	var pub []byte
	err := Readfile(&pub, libp2pkeypubpath)
	if err != nil {
		log.Fatal("Failed to read pubkey")
		return nil, err
	}

	return pub, nil
}
