package main

import (
	"fmt"
	"github.com/w33zl3p00tch/rsawrap"
)

func main() {
	passwd := []byte("SuperSecretPassword")
	keyLength := 2048 // Key length in bits

	// Create a key pair.
	privKey, pubKey, err := rsawrap.CreateKey(keyLength, passwd)
	if err != nil {
		panic(err)
	}

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
