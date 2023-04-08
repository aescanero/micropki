package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"time"

	"github.com/aescanero/micropki/secrets"
)

type CA struct {
	tpl          *x509.Certificate
	caPEM        *bytes.Buffer
	caPrivKeyPEM *bytes.Buffer
	keyType      string
	privateKey   PrivateKey
	//pub          *crypto.PrivateKey
}
type PrivateKey struct {
	rsaPrivateKey   *rsa.PrivateKey
	ecdsaPrivateKey *ecdsa.PrivateKey
}

func (myca *CA) SetupCA() {
	myca.keyType = "ecdsa"
	myca.tpl = &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Disasterproject"},
			Country:       []string{"ES"},
			Province:      []string{"Seville"},
			Locality:      []string{"Seville"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
}

func (myca *CA) NewCA() error {
	// create our private and public key
	var err error
	var priv crypto.PrivateKey
	var pub crypto.PublicKey
	log.Println("Generate new key")
	if myca.keyType == "ecdsa" {
		myca.privateKey.ecdsaPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		priv = myca.privateKey.ecdsaPrivateKey
		pub = priv.(crypto.Signer).Public()
	} else {
		myca.privateKey.rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return err
		}
		priv = myca.privateKey.rsaPrivateKey
		pub = priv.(crypto.Signer).Public()
	}

	_, ok := priv.(crypto.Signer)
	if !ok {
		return errors.New("!!! x509: certificate private key does not implement crypto.Signer")
	}

	log.Println("Generate new certificate")
	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, myca.tpl, myca.tpl, pub, priv)
	if err != nil {
		return err
	}

	//Test CA
	myca.tpl, err = x509.ParseCertificate(caBytes)
	if err != nil {
		return err
	}

	// pem encode
	log.Println("PEM Encode")
	myca.caPEM = new(bytes.Buffer)
	pem.Encode(myca.caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	myca.caPrivKeyPEM = new(bytes.Buffer)
	pem.Encode(myca.caPrivKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})

	return nil
}

func (myca *CA) SaveToSecret(name string, namespace string) error {

	data := map[string][]byte{
		"tls.crt": myca.caPEM.Bytes(),
		"tls.key": myca.caPrivKeyPEM.Bytes(),
	}
	return (secrets.Create(name, namespace, data))
}

func (myca *CA) UpdateSecret(name string, namespace string) error {

	data := map[string][]byte{
		"tls.crt": myca.caPEM.Bytes(),
		"tls.key": myca.caPrivKeyPEM.Bytes(),
	}
	return (secrets.Update(name, namespace, data))
}

func (myca *CA) NeedInitialization(name string, namespace string) error {
	data, err := secrets.Get(name, namespace)
	if err != nil {
		return (err)
	}

	if len(data["tls.crt"]) == 0 || len(data["tls.key"]) == 0 {
		return (errors.New("need update"))
	}
	return nil
}

func (myca *CA) LoadFromSecret(name string, namespace string) error {
	var priv crypto.PrivateKey
	data, err := secrets.Get(name, namespace)
	if err != nil {
		return (err)
	}

	myca.caPEM = bytes.NewBuffer(data["tls.crt"])
	log.Println("caPEM loaded")
	myca.caPrivKeyPEM = bytes.NewBuffer(data["tls.key"])
	log.Println("caPrivKeyPEM loaded")
	der, _ := pem.Decode(myca.caPEM.Bytes())
	if err != nil || der.Type != "CERTIFICATE" {
		panic(err.Error())
	}

	log.Println("caPEM loaded")

	myca.tpl, _ = x509.ParseCertificate(der.Bytes)

	log.Println("tpl loaded")

	derKey, _ := pem.Decode(myca.caPrivKeyPEM.Bytes())
	if err != nil || der.Type != "CERTIFICATE" {
		panic(err.Error())
	}

	priv, err = x509.ParsePKCS8PrivateKey(derKey.Bytes)
	if err != nil {
		return err
	}

	_, ok := priv.(crypto.Signer)
	if !ok {
		return errors.New("!!! x509: certificate private key does not implement crypto.Signer")
	}

	switch priv.(type) {
	case *ecdsa.PrivateKey:
		myca.privateKey.ecdsaPrivateKey = priv.(*ecdsa.PrivateKey)
		myca.keyType = "ecdsa"
		log.Println("Load ECDSA Key")
	case *rsa.PrivateKey:
		myca.keyType = "rsa"
		myca.privateKey.rsaPrivateKey = priv.(*rsa.PrivateKey)
		log.Println("Load RSA Key")
	default:
		return errors.New("unsupported private key supplied as a public key, cannot convert")
	}

	return nil
}
