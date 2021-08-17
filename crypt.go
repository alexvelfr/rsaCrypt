package rsacrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io/ioutil"
)

var (
	ErrKeyNotLoaded error = errors.New("key not loaded")
)

type Cryptor struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewCryptor(privateKeyPath, publicKeyPath string) (*Cryptor, error) {
	c := &Cryptor{}
	pubBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}
	priBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	pub, err := c.bytesToPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	priv, err := c.bytesToPrivateKey(priBytes)
	if err != nil {
		return nil, err
	}
	c.privateKey = priv
	c.publicKey = pub
	return c, nil
}

func (c *Cryptor) Encrypt(data string) (string, error) {
	if c.publicKey == nil {
		return "", ErrKeyNotLoaded
	}
	encData, err := rsa.EncryptPKCS1v15(rand.Reader, c.publicKey, []byte(data))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encData), nil
}

func (c *Cryptor) Decrypt(data string) (string, error) {
	if c.privateKey == nil {
		return "", ErrKeyNotLoaded
	}
	encData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	decData, err := rsa.DecryptPKCS1v15(rand.Reader, c.privateKey, encData)
	if err != nil {
		return "", err
	}
	return string(decData), nil
}

func (c *Cryptor) GenerateKeys(pubKeyPath, privKeyPath string) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	c.privateKey = privKey
	c.publicKey = &privKey.PublicKey
	btPrivateKey := x509.MarshalPKCS1PrivateKey(privKey)
	btPubKey := x509.MarshalPKCS1PublicKey(c.publicKey)
	ioutil.WriteFile(pubKeyPath, btPubKey, 0644)
	ioutil.WriteFile(privKeyPath, btPrivateKey, 0644)
}

func (c *Cryptor) bytesToPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(priv)
}

func (c *Cryptor) bytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	return x509.ParsePKCS1PublicKey(pub)
}
