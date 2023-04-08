package validatingwebhookconfiguration

import (
	"context"
	"log"

	b64 "encoding/base64"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func UpdateValidatingWebhookConfiguration(name string, pem []byte) error {
	log.Println("Obtain Config")
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	// create the client
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	log.Println("Update ValidatingWebhookConfigurations")
	validatingWebhookConfigurationClient := client.AdmissionregistrationV1().ValidatingWebhookConfigurations()
	patch := []byte(`[{"op":"replace","path":"/webhooks/0/clientConfig/caBundle","value": "` + b64.StdEncoding.EncodeToString(pem) + `"}]`)
	_, err = validatingWebhookConfigurationClient.Patch(context.TODO(), name, types.JSONPatchType, patch, metav1.PatchOptions{})
	if err != nil {
		panic(err.Error())
	}
	return nil
}
