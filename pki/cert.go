package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type CERT struct {
	cert           *x509.Certificate
	certPrivKey    *rsa.PrivateKey
	certPEM        *bytes.Buffer
	caPEM          *bytes.Buffer
	certPrivKeyPEM *bytes.Buffer
	//fqdn           string
	serverCert    tls.Certificate
	serverTLSConf *tls.Config
	clientTLSConf *tls.Config
}

func (mycert *CERT) setupCERT() {
	mycert.cert = &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Disasterproject"},
			Country:       []string{"ES"},
			Province:      []string{"Seville"},
			Locality:      []string{"Seville"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}

func (mycert *CERT) newCERT(name string, defaultNamespace ...string) error {
	var err error
	mycert.certPrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	var myca CA
	myca.SetupCA()
	myca.LoadFromSecret(name)

	certBytes, err := x509.CreateCertificate(rand.Reader, mycert.cert, myca.ca, &mycert.certPrivKey.PublicKey, myca.caPrivKey)
	if err != nil {
		return err
	}

	mycert.caPEM = myca.caPEM

	mycert.certPEM = new(bytes.Buffer)
	pem.Encode(mycert.certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	mycert.certPrivKeyPEM = new(bytes.Buffer)
	pem.Encode(mycert.certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(mycert.certPrivKey),
	})

	mycert.serverCert, err = tls.X509KeyPair(mycert.certPEM.Bytes(), mycert.certPrivKeyPEM.Bytes())
	if err != nil {
		return err
	}

	mycert.serverTLSConf = &tls.Config{
		Certificates: []tls.Certificate{mycert.serverCert},
	}

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(myca.caPEM.Bytes())
	mycert.clientTLSConf = &tls.Config{
		RootCAs: certpool,
	}

	return nil
}

func (mycert *CERT) SaveToSecret(name string, defaultNamespace ...string) error {
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
			"ca.crt":   mycert.caPEM.Bytes(),
			"cert.crt": mycert.certPEM.Bytes(),
			"cert.key": mycert.certPrivKeyPEM.Bytes(),
		},
	}

	if _, err = secrets.Create(context.TODO(), secret, metav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}

func (mycert *CERT) LoadFromSecret(name string, defaultNamespace ...string) error {
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

	mycert.caPEM = bytes.NewBuffer(secret.Data["ca.crt"])
	mycert.certPEM = bytes.NewBuffer(secret.Data["cert.crt"])
	mycert.certPrivKeyPEM = bytes.NewBuffer(secret.Data["cert.key"])

	return nil
}
