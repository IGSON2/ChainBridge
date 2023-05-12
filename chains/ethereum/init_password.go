package ethereum

import (
	"fmt"
	"os"

	"github.com/ChainSafe/chainbridge-core/crypto"
	"github.com/ChainSafe/chainbridge-utils/keystore"
)

var keyMapping = map[string]string{
	"ethereum":  "secp256k1",
	"substrate": "sr25519",
}

// SendToPasswordKeypair attempts to load the encrypted key file for the provided address,
// prompting the user for the password.
func SendToPasswordKeypair(addr, chainType, path, password string) (crypto.Keypair, error) {
	if password == "" {
		return nil, fmt.Errorf("password is empty")
	}
	path = fmt.Sprintf("%s/%s.key", path, addr)
	// Make sure key exists before prompting password
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("key file not found: %s", path)
	}
	var pswd []byte = []byte(password)

	kp, err := keystore.ReadFromFileAndDecrypt(path, pswd, keyMapping[chainType])
	if err != nil {
		return nil, err
	}

	return kp, nil
}
