package ca

import (
	"errors"
	"log"

	"github.com/aescanero/micropki/pki"
	"github.com/aescanero/micropki/vars"
	"github.com/aescanero/openldap-controller/utils"
	"github.com/spf13/cobra"
)

func init() {
	CACmd.AddCommand(CreateCACmd)
	CreateCACmd.Flags().StringVarP(&name, "name", "", "", "Name of the secret where the CA is saved (Default: micropki-ca)")
	CreateCACmd.Flags().StringVarP(&namespace, "namespace", "", "", "Name of the namespace where the secret of the CA is saved (Default: where is running micropki)")
	CreateCACmd.Flags().StringVarP(&cafile, "cafile", "", "", "File Path where the CA Cert is saved (Disable save to secret, also need cakeyfile)")
	CreateCACmd.Flags().StringVarP(&cakeyfile, "cakeyfile", "", "", "File Path where the CA Private Key is saved (Disable save to secret, also need cafile)")
}

var CreateCACmd = &cobra.Command{
	Use:   "loadorcreate",
	Short: "Create a new CA and save in a secret",
	Long:  `Create a new CA and save in a secret`,
	Run: func(cmd *cobra.Command, args []string) {
		myca := new(pki.CA)
		myca.SetupCA()
		err := myca.NewCA()
		if err != nil {
			log.Fatal(err)
		}
		if cafile != "" && cakeyfile != "" {
			err = myca.SaveToFile(cafile, cakeyfile)
			panic(err.Error())
		} else if cafile != "" || cakeyfile != "" {
			panic(errors.New("please use cafile and cakeyfile arguments"))
		}
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
			err = myca.SaveToSecret(name, namespace)
			if err != nil {
				panic(err.Error())
			}
		}
	},
}
