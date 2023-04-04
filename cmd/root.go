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

package cmd

import (
	"fmt"
	"os"

	"github.com/aescanero/micropki/cmd/ca"
	"github.com/aescanero/micropki/cmd/cert"
	"github.com/aescanero/micropki/cmd/validate"
	"github.com/spf13/cobra"
)

var (
	RootCmd = &cobra.Command{
		Use:   "micropki",
		Short: "micropki is a simple tool to manage a self service pki in kubernetes",
		Long: `"micropki is part of the Disasterproject's Openldap Operator
		Author:  Alejandro Escanero Blanco <aescanero@disasterproject.com>
		license: Apache 2.0`,
		Run: func(cmd *cobra.Command, args []string) {
			// Do Stuff Here
		},
	}
)

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.AddCommand(ca.CACmd)
	RootCmd.AddCommand(cert.CERTCmd)
	RootCmd.AddCommand(versionCmd)
	RootCmd.AddCommand(validate.ValidatePkiCmd)
}