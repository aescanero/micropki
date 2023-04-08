package secrets

import (
	"context"
	"log"

	b64 "encoding/base64"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func Update(name string, namespace string, data map[string][]byte) error {
	// create the in the cluster configuration
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	// create the client
	log.Println("Obtain Config")
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	log.Println("Update Secret")
	secrets := client.CoreV1().Secrets(namespace)
	patch := []byte(`[{"op":"replace","path":"/data/tls.crt","value": "` + b64.StdEncoding.EncodeToString(data["tls.crt"]) + `"}]`)
	//log.Println(string(patch))
	if _, err = secrets.Patch(context.TODO(), name, types.JSONPatchType, patch, metav1.PatchOptions{}); err != nil {
		return err
	}

	patch = []byte(`[{"op":"replace","path":"/data/tls.key","value": "` + b64.StdEncoding.EncodeToString(data["tls.key"]) + `"}]`)
	//log.Println(string(patch))
	if _, err = secrets.Patch(context.TODO(), name, types.JSONPatchType, patch, metav1.PatchOptions{}); err != nil {
		return err
	}

	log.Println("Secret updated")

	return nil
}
