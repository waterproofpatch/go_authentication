package authentication

import (
	"context"
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

func GetSecret(secretName string, kvName string) (string, error) {
	fmt.Println("Getting secret...")
	// mySecretValue := "secretValue"
	vaultURI := fmt.Sprintf("https://%s.vault.azure.net/", kvName)

	// Create a credential using the NewDefaultAzureCredential type.
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
		return "", err
	}

	// Establish a connection to the Key Vault client
	client, err := azsecrets.NewClient(vaultURI, cred, nil)

	// Create a secret
	// params := azsecrets.SetSecretParameters{Value: &mySecretValue}
	// _, err = client.SetSecret(context.TODO(), secretName, params, nil)
	if err != nil {
		log.Fatalf("failed to create a secret: %v", err)
		return "", err
	}

	// Get a secret. An empty string version gets the latest version of the secret.
	version := ""
	resp, err := client.GetSecret(context.TODO(), secretName, version, nil)
	if err != nil {
		log.Fatalf("failed to get the secret: %v", err)
		return "", err
	}

	// fmt.Printf("secretValue: %s\n", *resp.Value)

	// List secrets
	// pager := client.NewListSecretsPager(nil)
	// for pager.More() {
	// 	page, err := pager.NextPage(context.TODO())
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	for _, secret := range page.Value {
	// 		fmt.Printf("Secret ID: %s\n", *secret.ID)
	// 	}
	// }

	// Delete a secret. DeleteSecret returns when Key Vault has begun deleting the secret.
	// That can take several seconds to complete, so it may be necessary to wait before
	// performing other operations on the deleted secret.
	// delResp, err := client.DeleteSecret(context.TODO(), secretName, nil)
	// if err != nil {
	// 	log.Fatalf("failed to delete secret: %v", err)
	// }

	// fmt.Println(delResp.ID.Name() + " has been deleted")
	return *resp.Value, nil
}
