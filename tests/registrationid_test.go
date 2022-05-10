package tests

import (
	"fmt"
	"github.com/Luca3317/libsignalcopy/util/keyhelper"
	"testing"
)

func TestRegistrationID(t *testing.T) {
	regID := keyhelper.GenerateRegistrationID()
	fmt.Println(regID)
}
