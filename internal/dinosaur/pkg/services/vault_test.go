package services

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSecretsManagerConnection(t *testing.T) {
	service, err := NewAwsVaultService()
	assert.NoError(t, err)

	name := "this_is_the_test_secret"
	err = service.SetSecretString(name, "this_is_test_secret_value", "")
	assert.NoError(t, err)

	secret, err := service.GetSecretString(name)
	assert.NoError(t, err)
	print(secret)

	err = service.DeleteSecretString(name)
	assert.NoError(t, err)
}
