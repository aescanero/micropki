package ca

import (
	"log"

	"github.com/aescanero/micropki/pki"
	"github.com/aescanero/micropki/vars"
	"github.com/aescanero/openldap-controller/utils"
	"github.com/spf13/cobra"
)

func init() {
	CACmd.AddCommand(loadOrCreateCACmd)
	loadOrCreateCACmd.Flags().StringVarP(&name, "name", "", "", "Name of the secret where the CA is saved (Default: micropki-ca)")
	loadOrCreateCACmd.Flags().StringVarP(&namespace, "namespace", "", "", "Name of the namespace where the secret of the CA is saved (Default: where is running micropki)")
}

var loadOrCreateCACmd = &cobra.Command{
	Use:   "loadorcreate",
	Short: "Create a new CA and save in a secret",
	Long:  `Create a new CA and save in a secret`,
	Run: func(cmd *cobra.Command, args []string) {
		myca := new(pki.CA)
		myca.SetupCA()

		if name == "" {
			name = utils.GetEnv("SECRETNAME", "micropki-ca")
		}
		namespace, err := vars.ValidateNamespace(namespace)
		if err != nil {
			panic(err.Error())
		}

		err = myca.LoadFromSecret(name, namespace)
		if err != nil {
			log.Fatal("Secret can't be loaded")
			log.Fatal(err.Error())
			err = myca.NewCA()
			if err != nil {
				panic(err.Error())
			}
			myca.SaveToSecret(name, namespace)
		}
	}}
