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

package ca

import (
	"log"

	"github.com/aescanero/micropki/pki"
	"github.com/aescanero/micropki/vars"
	"github.com/aescanero/openldap-controller/utils"
	"github.com/spf13/cobra"
)

var (
	name      string
	namespace string
)

func init() {
	CACmd.AddCommand(newCACmd)
	newCACmd.Flags().StringVarP(&name, "name", "", "", "Name of the secret where the CA is saved (Default: micropki-ca)")
	newCACmd.Flags().StringVarP(&namespace, "namespace", "", "", "Name of the namespace where the secret of the CA is saved (Default: where is running micropki)")
}

var newCACmd = &cobra.Command{
	Use:   "new",
	Short: "Create a new CA and save in a secret",
	Long:  `Create a new CA and save in a secret`,
	Run: func(cmd *cobra.Command, args []string) {
		myca := new(pki.CA)
		myca.SetupCA()
		err := myca.NewCA()
		if err != nil {
			log.Fatal(err)
		}
		if name == "" {
			name = utils.GetEnv("SECRETNAME", "micropki-ca")
		}
		namespace, err := vars.ValidateNamespace(namespace)
		if err != nil {
			panic(err.Error())
		}
		err = myca.SaveToSecret(name, namespace)
		if err != nil {
			log.Fatal(err)
		}
	},
}
