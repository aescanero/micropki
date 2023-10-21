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
	"net"
	"net/mail"
	"net/url"
	"os"
	"time"

	"github.com/aescanero/micropki/secrets"
	validatingwebhookconfiguration "github.com/aescanero/micropki/validatingWebhookConfiguration"
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

func (mycert *CERT) GetPEM() ([]byte, error) {

	if mycert.certPEM == nil {
		return make([]byte, 0), errors.New("not initialized")
	}

	return mycert.certPEM.Bytes(), nil

}

func (mycert *CERT) GetPrivKeyPEM() ([]byte, error) {

	if mycert.certPrivKeyPEM == nil {
		return make([]byte, 0), errors.New("not initialized")
	}

	return mycert.certPrivKeyPEM.Bytes(), nil
}

func (mycert *CERT) SetupCERT(client bool, hosts []string, commonName string) {
	mycert.tpl = &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Disasterproject"},
			Country:       []string{"ES"},
			Province:      []string{"Seville"},
			Locality:      []string{"Seville"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    commonName,
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

func (mycert *CERT) NewCERT(caname string, caNamespace ...string) error {
	var err error
	var priv crypto.PrivateKey
	var certBytes []byte

	myca := new(CA)
	myca.SetupCA()
	myca.LoadFromSecret(caname, caNamespace[0])

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

func (mycert *CERT) NewCERTFromFile(cafile string, cafilekey string) error {
	var err error
	var priv crypto.PrivateKey
	var certBytes []byte

	myca := new(CA)
	myca.SetupCA()
	err = myca.LoadFromFile(cafile, cafilekey)
	if err != nil {
		myca.NewCA()
		myca.SaveToFile(cafile, cafilekey)
	}

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

	return nil
}

func (mycert *CERT) SaveToSecret(name string, namespace string) error {
	data := map[string][]byte{
		"tls.crt": mycert.certPEM.Bytes(),
		"tls.key": mycert.certPrivKeyPEM.Bytes(),
	}
	return (secrets.Create(name, namespace, data))
}

func (mycert *CERT) SaveToFile(certfile string, certkeyfile string) error {

	err := os.WriteFile(certfile, mycert.certPEM.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
		return err
	}

	err = os.WriteFile(certkeyfile, mycert.certPrivKeyPEM.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
		return err
	}

	return nil
}

func (mycert *CERT) UpdateSecret(name string, namespace string) error {

	data := map[string][]byte{
		"tls.crt": mycert.certPEM.Bytes(),
		"tls.key": mycert.certPrivKeyPEM.Bytes(),
	}
	return (secrets.Update(name, namespace, data))
}

func (mycert *CERT) NeedInitialization(name string, namespace string) error {
	data, err := secrets.Get(name, namespace)
	if err != nil {
		return (err)
	}

	if len(data["tls.crt"]) == 0 || len(data["tls.key"]) == 0 {
		return (errors.New("need update"))
	}
	return nil
}

func (mycert *CERT) LoadFromSecret(name string, namespace string) error {

	var priv crypto.PrivateKey

	data, err := secrets.Get(name, namespace)
	if err != nil {
		return (err)
	}

	mycert.certPEM = bytes.NewBuffer(data["tls.crt"])
	mycert.certPrivKeyPEM = bytes.NewBuffer(data["tls.key"])

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

func (mycert *CERT) LoadFromFile(certfile string, certfilekey string) error {

	var priv crypto.PrivateKey

	cafileBuf, err := os.ReadFile(certfile)
	if err != nil {
		return (err)
	}
	mycert.certPEM = bytes.NewBuffer(cafileBuf)
	cafilekeyBuf, err := os.ReadFile(certfilekey)
	if err != nil {
		return (err)
	}
	mycert.certPrivKeyPEM = bytes.NewBuffer(cafilekeyBuf)

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

func (mycert *CERT) UpdateValidatingWebhookConfiguration(name string) error {
	return (validatingwebhookconfiguration.UpdateValidatingWebhookConfiguration("openldap-operator-validating-webhook-configuration", mycert.certPEM.Bytes()))
}
