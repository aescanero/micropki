package webhook

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
	webhook     string
)

func init() {
	UpdateCmd.Flags().StringVarP(&caname, "caname", "", "", "Name of the secret where the CA is saved (Default: micropki-ca)")
	UpdateCmd.Flags().StringVarP(&certname, "certname", "", "", "Name of the secret where the CERT is saved (Default: micropki-cert)")
	UpdateCmd.Flags().StringVarP(&namespace, "certnamespace", "", "", "Name of the namespace where the secret of the CERT is saved (Default: where is running micropki)")
	UpdateCmd.Flags().BoolVarP(&client, "client", "", false, "The cert is for a server or a cliente (default: server)")
	UpdateCmd.Flags().StringVarP(&caNamespace, "canamespace", "", "", "Name of the namespace where the secret of the CA is saved (Default: where is running micropki)")
	UpdateCmd.Flags().StringVarP(&fqdns, "hosts", "", "", "FQDN Host list separated by ','")
	UpdateCmd.Flags().StringVarP(&webhook, "webhook", "", "", "Name of the webhook")
	UpdateCmd.Flags().StringVarP(&commonname, "commonname", "", "", "Common Name of the CERT','")
}

var UpdateCmd = &cobra.Command{
	Use:   "update",
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
		err = myca.NeedInitialization(caname, caNamespace)
		if err != nil {
			if err.Error() != "need update" {
				panic(err.Error())
			} else {
				err = myca.NewCA()
				if err != nil {
					panic(err.Error())
				}
				err = myca.UpdateSecret(caname, caNamespace)
				if err != nil {
					panic(err.Error())
				}
			}
		}
		mycert := new(pki.CERT)
		mycert.SetupCERT(client, strings.Split(fqdns, ","), commonname)
		err = mycert.NeedInitialization(certname, namespace)
		if err != nil {
			if err.Error() != "need update" {
				panic(err.Error())
			} else {
				err = mycert.NewCERT(caname, caNamespace)
				if err != nil {
					panic(err.Error())
				}
				err = mycert.UpdateSecret(certname, namespace)
				if err != nil {
					panic(err.Error())
				}
				err = mycert.UpdateValidatingWebhookConfiguration(webhook)
				if err != nil {
					panic(err.Error())
				}
			}
		}
	}}
