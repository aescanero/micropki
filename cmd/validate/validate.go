package validate

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
	webhook     string
)

func init() {
	ValidatePkiCmd.Flags().StringVarP(&caname, "caname", "", "", "Name of the secret where the CA is saved (Default: micropki-ca)")
	ValidatePkiCmd.Flags().StringVarP(&certname, "certname", "", "", "Name of the secret where the CERT is saved (Default: micropki-cert)")
	ValidatePkiCmd.Flags().StringVarP(&namespace, "certnamespace", "", "", "Name of the namespace where the secret of the CERT is saved (Default: where is running micropki)")
	ValidatePkiCmd.Flags().BoolVarP(&client, "client", "", false, "The cert is for a server or a cliente (default: server)")
	ValidatePkiCmd.Flags().StringVarP(&caNamespace, "canamespace", "", "", "Name of the namespace where the secret of the CA is saved (Default: where is running micropki)")
	ValidatePkiCmd.Flags().StringVarP(&fqdns, "hosts", "", "", "FQDN Host list separated by ','")
	ValidatePkiCmd.Flags().StringVarP(&webhook, "webhook", "", "", "Name of the webhook")
}

var ValidatePkiCmd = &cobra.Command{
	Use:   "validate",
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
		mycert.SetupCERT(false, strings.Split(fqdns, ","))
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
		mycert.UpdateValidatingWebhookConfiguration(webhook)
	}}
