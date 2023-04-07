package secrets

import (
	"context"
	"log"

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
	log.Println("Save Secret")
	secrets := client.CoreV1().Secrets(namespace)
	tlscrt := string(data["tls.crt"])
	patch := []byte(`[{"op":"replace,"path":"data/tls.crt","value": "` + tlscrt + `"}]`)
	if _, err = secrets.Patch(context.TODO(), name, types.JSONPatchType, patch, metav1.PatchOptions{}); err != nil {
		return err
	}

	tlskey := string(data["tls.crt"])
	patch = []byte(`[{"op":"replace,"path":"data/tls.key","value": "` + tlskey + `"}]`)
	if _, err = secrets.Patch(context.TODO(), name, types.JSONPatchType, patch, metav1.PatchOptions{}); err != nil {
		return err
	}

	log.Println("Secret created")

	return nil
}
