/*Copyright [2023] [Alejandro Escanero Blanco <aescanero@disasterproject.com>]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.*/

package cert

import (
	"errors"
	"log"
	"strings"

	"github.com/aescanero/micropki/pki"
	"github.com/aescanero/micropki/vars"
	"github.com/aescanero/openldap-controller/utils"
	"github.com/spf13/cobra"
)

func init() {
	CERTCmd.AddCommand(newCERTCmd)
	newCERTCmd.Flags().StringVarP(&caname, "caname", "", "", "Name of the secret where the CA is saved (Default: micropki-ca)")
	newCERTCmd.Flags().StringVarP(&certname, "certname", "", "", "Name of the secret where the CERT is saved (Default: micropki-cert)")
	newCERTCmd.Flags().StringVarP(&namespace, "certnamespace", "", "", "Name of the namespace where the secret of the CERT is saved (Default: where is running micropki)")
	newCERTCmd.Flags().BoolVarP(&client, "client", "", false, "The cert is for a server or a cliente (default: server)")
	newCERTCmd.Flags().StringVarP(&caNamespace, "canamespace", "", "", "Name of the namespace where the secret of the CA is saved (Default: where is running micropki)")
	newCERTCmd.Flags().StringVarP(&fqdns, "hosts", "", "", "FQDN Host list separated by ','")
	newCERTCmd.Flags().StringVarP(&cafile, "cafile", "", "", "File Path where the CA Cert is saved (Disable save to secret, also need cakeyfile)")
	newCERTCmd.Flags().StringVarP(&cakeyfile, "cakeyfile", "", "", "File Path where the CA Private Key is saved (Disable save to secret, also need cafile)")
	newCERTCmd.Flags().StringVarP(&certfile, "certfile", "", "", "File Path where the CA Cert is saved (Disable save to secret, also need certkeyfile)")
	newCERTCmd.Flags().StringVarP(&certkeyfile, "certkeyfile", "", "", "File Path where the CA Private Key is saved (Disable save to secret, also need certfile)")
	newCERTCmd.Flags().StringVarP(&commonname, "commonname", "", "", "Common Name of the CERT','")
}

var newCERTCmd = &cobra.Command{
	Use:   "new",
	Short: "Create a new cert and save in a secret, needs the secret ca",
	Long:  `Create a new cert and save in a secret, needs the secret ca`,
	Run: func(cmd *cobra.Command, args []string) {
		mycert := pki.CERT{}
		hosts := strings.Split(fqdns, ",")
		mycert.SetupCERT(client, hosts, commonname)
		if cafile != "" && cakeyfile != "" && certfile != "" && certkeyfile != "" {
			err := mycert.NewCERTFromFile(cafile, cakeyfile)
			if err != nil {
				panic(err.Error())
			}
			err = mycert.SaveToFile(certfile, certkeyfile)
			if err != nil {
				panic(err.Error())
			}
		} else if cafile != "" || cakeyfile != "" || certfile != "" || certkeyfile != "" {
			panic(errors.New("please use cafile, cakeyfile, certfile, certkeyfile arguments"))
		} else {
			if caname == "" {
				caname = utils.GetEnv("CASECRETNAME", "micropki-ca")
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
			err = mycert.NewCERT(caname, caNamespace)
			if err != nil {
				log.Fatal(err)
			}
			if certname == "" {
				certname = utils.GetEnv("CERTSECRETNAME", "micropki-cert")
			}
			err = mycert.SaveToSecret(certname, namespace)
			if err != nil {
				log.Fatal(err)
			}
		}
	},
}
