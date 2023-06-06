package initpki

import (
	"strings"

	"github.com/aescanero/micropki/pki"
	"github.com/aescanero/micropki/vars"
	"github.com/aescanero/openldap-controller/utils"
	"github.com/spf13/cobra"
)

var (
	caname      string
	certname    string
	namespace   string
	client      bool
	caNamespace string
	fqdns       string
	commonname  string
)

func init() {
	InitPkiCmd.Flags().StringVarP(&caname, "caname", "", "", "Name of the secret where the CA is saved (Default: micropki-ca)")
	InitPkiCmd.Flags().StringVarP(&certname, "certname", "", "", "Name of the secret where the CERT is saved (Default: micropki-cert)")
	InitPkiCmd.Flags().StringVarP(&namespace, "certnamespace", "", "", "Name of the namespace where the secret of the CERT is saved (Default: where is running micropki)")
	InitPkiCmd.Flags().BoolVarP(&client, "client", "", false, "The cert is for a server or a cliente (default: server)")
	InitPkiCmd.Flags().StringVarP(&caNamespace, "canamespace", "", "", "Name of the namespace where the secret of the CA is saved (Default: where is running micropki)")
	InitPkiCmd.Flags().StringVarP(&fqdns, "hosts", "", "", "FQDN Host list separated by ','")
	InitPkiCmd.Flags().StringVarP(&commonname, "commonname", "", "", "Common Name of the certificate")
}

var InitPkiCmd = &cobra.Command{
	Use:   "initpki",
	Short: "Prepare all the pki stuff",
	Long:  `Prepare all the pki stuff`,
	Run: func(cmd *cobra.Command, args []string) {
		myca := new(pki.CA)
		myca.SetupCA()

		if caname == "" {
			caname = utils.GetEnv("CA_SECRET_NAME", "micropki-ca")
		}
		if certname == "" {
			certname = utils.GetEnv("CERT_SECRET_NAME", "micropki-cert")
		}
		caNamespace, err := vars.ValidateNamespace(caNamespace)
		if err != nil {
			panic(err.Error())
		}
		namespace, err := vars.ValidateNamespace(namespace)
		if err != nil {
			panic(err.Error())
		}
		err = myca.LoadFromSecret(caname, caNamespace)
		if err != nil {
			myca.NewCA()
			myca.SaveToSecret(caname, caNamespace)
		}
		mycert := new(pki.CERT)
		mycert.SetupCERT(client, strings.Split(fqdns, ","), commonname)
		err = mycert.LoadFromSecret(certname, namespace)
		if err != nil {
			err = mycert.NewCERT(caname, caNamespace)
			if err != nil {
				panic(err.Error())
			}
			err = mycert.SaveToSecret(certname, namespace)
			if err != nil {
				panic(err.Error())
			}
		}
	}}
