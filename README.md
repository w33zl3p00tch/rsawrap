# rsawrap
Package rsawrap provides handy wrappers for creating RSA keys and encrypting or decrypting messages with RSA-OAEP.

## Example
```go
package main

import (
	"fmt"
	"github.com/w33zl3p00tch/rsawrap"
)

func main() {
	passwd := "SuperSecretPassword"
	keyLength := 2048 // Key length in bits

	// Create a key pair.
	privKey, pubKey, _ := rsawrap.CreateKey(keyLength, passwd)

	fmt.Println(string(privKey))
	fmt.Println(string(pubKey))

	msg := []byte("This is an example message.")

	// Encrypt the message.
	ciphertext, err := rsawrap.EncryptOAEP(msg, pubKey)
	if err != nil {
		panic(err)
	}

	fmt.Println("Ciphertext:", ciphertext)

	// Decrypt the ciphertext.
	plaintext, err := rsawrap.DecryptOAEP(ciphertext, privKey, passwd)
	if err != nil {
		panic(err)
	}

	fmt.Printf("\nPlaintext:\n%s\n", string(plaintext))
}
```

## License
This package is licensed under a BSD-style license as stated in the LICENSE file.
