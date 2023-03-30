package pki

import (
	"bytes"
	"context"
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
	"os"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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

func (myca *CA) SaveToSecret(name string, namespaces ...string) error {
	// create the in the cluster configuration
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	var namespace string
	log.Println("Verify namespace")
	if len(namespaces) == 0 || namespaces == nil {
		namespace_b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			panic(err)
		}
		log.Println("Loading namespace: " + string(namespace_b))
		namespace = string(namespace_b)
	} else {
		log.Println("Loading namespace")
		namespace = namespaces[0]
	}

	// create the client
	log.Println("Obtain Config")
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	log.Println("Save Secret")
	secrets := client.CoreV1().Secrets(namespace)
	secret := &v1.Secret{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{
			"app.kubernetes.io/created-by": "micropki",
			"app.kubernetes.io/part-of":    "micropki",
		}},
		Immutable: new(bool),
		Type:      v1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": myca.caPEM.Bytes(),
			"tls.key": myca.caPrivKeyPEM.Bytes(),
		},
	}

	if _, err = secrets.Create(context.TODO(), secret, metav1.CreateOptions{}); err != nil {
		return err
	}

	log.Println("Secret created")

	return nil
}

func (myca *CA) LoadFromSecret(name string, namespaces ...string) error {
	var namespace string
	var priv crypto.PrivateKey

	// create the in the cluster configuration
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	log.Println("Verify namespace")
	if len(namespaces) == 0 || namespaces == nil {
		namespace_b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			panic(err)
		}
		log.Println("Loading namespace: " + string(namespace_b))
		namespace = string(namespace_b)
	} else {
		log.Println("Loading namespace")
		namespace = namespaces[0]
	}

	// create the client
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	log.Println("Conf loaded")

	secrets := client.CoreV1().Secrets(namespace)
	secret, err := secrets.Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		log.Fatal(err.Error())
		return err
	}

	log.Println("Secret loaded")

	myca.caPEM = bytes.NewBuffer(secret.Data["tls.crt"])
	log.Println("caPEM loaded")
	myca.caPrivKeyPEM = bytes.NewBuffer(secret.Data["tls.key"])
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
