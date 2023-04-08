package vars

import (
	"log"
	"os"
)

func ValidateNamespace(namespace string) (string, error) {
	if namespace == "" {
		namespace_b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			return "", err
		}
		log.Println("Found namespace: " + string(namespace_b))
		return string(namespace_b), nil
	}
	return namespace, nil
}
