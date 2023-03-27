package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type CA struct {
	ca           *x509.Certificate
	caPrivKey    *rsa.PrivateKey
	caPEM        *bytes.Buffer
	caPrivKeyPEM *bytes.Buffer
}

func (myca *CA) SetupCA() {
	myca.ca = &x509.Certificate{
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
	}
}

func (myca *CA) NewCA() error {
	// create our private and public key
	var err error
	myca.caPrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, myca.ca, myca.ca, &myca.caPrivKey.PublicKey, myca.caPrivKey)
	if err != nil {
		return err
	}

	// pem encode
	myca.caPEM = new(bytes.Buffer)
	pem.Encode(myca.caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	myca.caPrivKeyPEM = new(bytes.Buffer)
	pem.Encode(myca.caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(myca.caPrivKey),
	})

	return nil
}

func (myca *CA) SaveToSecret(name string, defaultNamespace ...string) error {
	// create the in the cluster configuration
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	namespace_b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		panic(err)
	}

	namespace := string(namespace_b)

	if defaultNamespace[0] != "" {
		namespace = defaultNamespace[0]
	}

	// create the client
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

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
			"ca.crt": myca.caPEM.Bytes(),
			"ca.key": myca.caPrivKeyPEM.Bytes(),
		},
	}

	if _, err = secrets.Create(context.TODO(), secret, metav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}

func (myca *CA) LoadFromSecret(name string, defaultNamespace ...string) error {
	// create the in the cluster configuration
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	namespace_b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		panic(err)
	}

	namespace := string(namespace_b)

	if defaultNamespace[0] != "" {
		namespace = defaultNamespace[0]
	}

	// create the client
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	secrets := client.CoreV1().Secrets(namespace)
	secret, err := secrets.Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		panic(err.Error())
	}

	myca.caPEM = bytes.NewBuffer(secret.Data["ca.crt"])
	myca.caPrivKeyPEM = bytes.NewBuffer(secret.Data["ca.key"])

	return nil
}
