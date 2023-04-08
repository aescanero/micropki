package secrets

import (
	"context"
	"log"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func Create(name string, namespace string, data map[string][]byte) error {
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
	secret := &v1.Secret{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{
			"app.kubernetes.io/created-by": "micropki",
			"app.kubernetes.io/part-of":    "micropki",
		}},
		Immutable: new(bool),
		Type:      v1.SecretTypeTLS,
		Data:      data,
	}

	if _, err = secrets.Create(context.TODO(), secret, metav1.CreateOptions{}); err != nil {
		return err
	}

	log.Println("Secret created")

	return nil
}
