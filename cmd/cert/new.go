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
	"fmt"

	"github.com/spf13/cobra"
)

var name string

func init() {
	CERTCmd.AddCommand(newCERTCmd)
	newCERTCmd.Flags().StringVarP(&name, "certname", "", "", "Name of the secret where the CERT is saved (Default: micropki-cert)")
	newCERTCmd.Flags().StringVarP(&name, "certnamespace", "", "", "Name of the namespace where the secret of the CERT is saved (Default: where is running micropki)")
	newCERTCmd.Flags().StringVarP(&name, "caname", "", "", "Name of the secret where the CA is saved (Default: micropki-ca)")
	newCERTCmd.Flags().StringVarP(&name, "canamespace", "", "", "Name of the namespace where the secret of the CA is saved (Default: where is running micropki)")
}

var newCERTCmd = &cobra.Command{
	Use:   "new",
	Short: "Create a new cert and save in a secret, needs the secret ca",
	Long:  `Create a new cert and save in a secret, needs the secret ca`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Disasterproject's Openldap Controller v0.1 -- HEAD")
	},
}
