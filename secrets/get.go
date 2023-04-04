package secrets

import (
	"context"
	"log"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func Get(name string, namespace string) (map[string][]byte, error) {

	// create the in the cluster configuration
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	// create the client
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	log.Println("Conf loaded")

	secrets := client.CoreV1().Secrets(namespace)
	secret, err := secrets.Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		log.Fatal(err.Error())
		return nil, err
	}

	log.Println("Secret loaded")

	return secret.Data, nil
}
