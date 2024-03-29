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
	cafile      string
	cakeyfile   string
	certfile    string
	certkeyfile string
)

func init() {
}

var CERTCmd = &cobra.Command{
	Use:   "cert",
	Short: "CERT commands",
	Long:  `Manipulate CERTs`,
}
