// Package rsawrap provides handy wrappers for creating RSA keys and encrypting
// or decrypting messages with RSA-OAEP.
package rsawrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// EncryptOAEP encrypts a plaintext using a PEM encoded RSA public key.
func EncryptOAEP(msg []byte, pubKey []byte) ([]byte, error) {
	hash := sha256.New()
	block, _ := pem.Decode(pubKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// DecryptOAEP decrypts an RSA-OAEP encrypted message. If the password is
// not an empty string, it will try to decrypt a PEM-armored private key.
// Although there are no known attacks against SHA1 in this context, SHA256
// is used as hash algorithm.
func DecryptOAEP(msg []byte, key []byte, passwd string) ([]byte, error) {
	var err error
	hash := sha256.New()
	privateKeyBlock, _ := pem.Decode(key)
	var privKey *rsa.PrivateKey
	var prk []byte

	if passwd != "" {
		pw := []byte(passwd)
		dec := x509.DecryptPEMBlock
		if prk, err = dec(privateKeyBlock, pw); err != nil {
			return nil, err
		}
	} else {
		prk = privateKeyBlock.Bytes
	}

	privKey, err = x509.ParsePKCS1PrivateKey(prk)
	if err != nil {
		return nil, errors.New("private key error. " +
			"Corrupt key or invalid armor password.")
	}
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privKey, msg, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// CreateKey takes the key length in bits and a password as arguments and
// returns an RSA key pair in PEM format. If the password is an empty string, the
// private key PEM will not be encrypted.
func CreateKey(bits int, passwd string) ([]byte, []byte, error) {
	var err error
	rd := rand.Reader
	var key *rsa.PrivateKey
	if key, err = rsa.GenerateKey(rd, bits); err != nil {
		return nil, nil, err
	}

	// Convert the private key to PEM.
	prk := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	// Encrypt the PEM when passwd is not empty.
	if passwd != "" {
		pw := []byte(passwd)
		enc := x509.EncryptPEMBlock
		cipher := x509.PEMCipherAES256
		if prk, err = enc(rd, prk.Type, prk.Bytes, pw, cipher); err != nil {
			return nil, nil, err
		}
	}
	pemPrivKey := pem.EncodeToMemory(prk)

	// Extract and encode the public key.
	pubKey := key.PublicKey
	var asn1Bytes []byte
	if asn1Bytes, err = x509.MarshalPKIXPublicKey(&pubKey); err != nil {
		return nil, nil, err
	}
	pemKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	pemPubKey := pem.EncodeToMemory(pemKeyBlock)

	return pemPrivKey, pemPubKey, nil
}
