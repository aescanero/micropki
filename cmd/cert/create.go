package cert

import (
	"strings"

	"github.com/aescanero/micropki/pki"
	"github.com/aescanero/micropki/vars"
	"github.com/aescanero/openldap-controller/utils"
	"github.com/spf13/cobra"
)

func init() {
	CERTCmd.AddCommand(CreateCERTCmd)
	CreateCERTCmd.Flags().StringVarP(&caname, "caname", "", "", "Name of the secret where the CA is saved (Default: micropki-ca)")
	CreateCERTCmd.Flags().StringVarP(&certname, "certname", "", "", "Name of the secret where the CERT is saved (Default: micropki-cert)")
	CreateCERTCmd.Flags().StringVarP(&namespace, "certnamespace", "", "", "Name of the namespace where the secret of the CERT is saved (Default: where is running micropki)")
	CreateCERTCmd.Flags().BoolVarP(&client, "client", "", false, "The cert is for a server or a cliente (default: server)")
	CreateCERTCmd.Flags().StringVarP(&caNamespace, "canamespace", "", "", "Name of the namespace where the secret of the CA is saved (Default: where is running micropki)")
	CreateCERTCmd.Flags().StringVarP(&fqdns, "hosts", "", "", "FQDN Host list separated by ','")
	CreateCERTCmd.Flags().StringVarP(&commonname, "commonname", "", "", "Common Name of the CERT','")
}

var CreateCERTCmd = &cobra.Command{
	Use:   "loadorcreate",
	Short: "Create a new CERT and save in a secret",
	Long:  `Create a new CERT and save in a secret`,
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
			panic("Secret CA can't be loaded")
		}
		mycert := new(pki.CERT)
		mycert.SetupCERT(false, strings.Split(fqdns, ","), commonname)
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
