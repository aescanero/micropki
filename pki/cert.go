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
	"net"
	"net/mail"
	"net/url"
	"os"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type CERT struct {
	tpl            *x509.Certificate
	certPEM        *bytes.Buffer
	certPrivKeyPEM *bytes.Buffer
	//fqdn           string
	/* serverCert    tls.Certificate
	serverTLSConf *tls.Config
	clientTLSConf *tls.Config */
	priv crypto.PrivateKey
	//pub           *crypto.PrivateKey
}

func (mycert *CERT) SetupCERT(client bool, hosts []string) {
	mycert.tpl = &x509.Certificate{
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

	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			mycert.tpl.IPAddresses = append(mycert.tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(host); err == nil && email.Address == host {
			mycert.tpl.EmailAddresses = append(mycert.tpl.EmailAddresses, host)
		} else if uriName, err := url.Parse(host); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			mycert.tpl.URIs = append(mycert.tpl.URIs, uriName)
		} else {
			mycert.tpl.DNSNames = append(mycert.tpl.DNSNames, host)
		}
	}

	//pkcs12, ecdsa, client      bool

	if client {
		mycert.tpl.ExtKeyUsage = append(mycert.tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(mycert.tpl.IPAddresses) > 0 || len(mycert.tpl.DNSNames) > 0 || len(mycert.tpl.URIs) > 0 {
		mycert.tpl.ExtKeyUsage = append(mycert.tpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if len(mycert.tpl.EmailAddresses) > 0 {
		mycert.tpl.ExtKeyUsage = append(mycert.tpl.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}
}

func (mycert *CERT) NewCERT(caname string, namespaces ...string) error {
	var err error
	var priv crypto.PrivateKey
	var certBytes []byte

	myca := new(CA)
	myca.SetupCA()
	myca.LoadFromSecret(caname)

	if myca.keyType == "ecdsa" {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		pub := priv.(crypto.Signer).Public()
		certBytes, err = x509.CreateCertificate(rand.Reader, mycert.tpl, myca.tpl, pub, myca.privateKey.ecdsaPrivateKey)
		if err != nil {
			return err
		}

	} else {
		priv, err = rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return err
		}
		pub := priv.(crypto.Signer).Public()
		certBytes, err = x509.CreateCertificate(rand.Reader, mycert.tpl, myca.tpl, pub, myca.privateKey.ecdsaPrivateKey)
		if err != nil {
			return err
		}
	}

	mycert.certPEM = new(bytes.Buffer)
	pem.Encode(mycert.certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	mycert.certPrivKeyPEM = new(bytes.Buffer)
	pem.Encode(mycert.certPrivKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})

	/* mycert.serverCert, err = tls.X509KeyPair(mycert.certPEM.Bytes(), mycert.certPrivKeyPEM.Bytes())
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
	} */

	return nil
}

func (mycert *CERT) SaveToSecret(name string, namespaces ...string) error {

	var namespace string

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

	log.Println("Config loaded")
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
			"tls.crt": mycert.certPEM.Bytes(),
			"tls.key": mycert.certPrivKeyPEM.Bytes(),
		},
	}

	if _, err = secrets.Create(context.TODO(), secret, metav1.CreateOptions{}); err != nil {
		log.Fatal(err.Error())
		return err
	}

	log.Println("Secret created")
	return nil
}

func (mycert *CERT) LoadFromSecret(name string, namespaces ...string) error {

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

	secrets := client.CoreV1().Secrets(namespace)
	secret, err := secrets.Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		panic(err.Error())
	}

	mycert.certPEM = bytes.NewBuffer(secret.Data["tls.crt"])
	mycert.certPrivKeyPEM = bytes.NewBuffer(secret.Data["tls.key"])

	der, _ := pem.Decode(mycert.certPEM.Bytes())
	if err != nil || der.Type != "CERTIFICATE" {
		panic(err.Error())
	}
	mycert.tpl, _ = x509.ParseCertificate(der.Bytes)

	log.Println("tpl loaded")

	derKey, _ := pem.Decode(mycert.certPrivKeyPEM.Bytes())
	if err != nil || der.Type != "CERTIFICATE" {
		panic(err.Error())
	}

	priv, err = x509.ParsePKCS8PrivateKey(derKey.Bytes)

	if err != nil {
		return err
	}

	switch priv.(type) {
	case *ecdsa.PrivateKey:
		log.Println("Pre ECDSA")
		mycert.priv = priv //.(*ecdsa.PrivateKey)
	case *rsa.PrivateKey:
		mycert.priv = priv //.(*rsa.PrivateKey)
		log.Println("Load RSA2 Key")
	default:
		return errors.New("unsupported private key supplied as a public key, cannot convert")
	}
	return nil
}
