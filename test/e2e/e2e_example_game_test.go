package test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestE2eExampleGame(t *testing.T) {

	//run `zarf init`
	output, err := e2e.execZarfCommand("init", "--confirm")
	require.NoError(t, err, output)

	// Deploy the game
	output, err = e2e.execZarfCommand("package", "deploy", "../../build/zarf-package-appliance-demo-multi-games.tar.zst", "--confirm")
	require.NoError(t, err, output)

	// Establish the port-forward into the game service
	err = e2e.execZarfBackgroundCommand("connect", "doom", "--local-port=22333")
	require.NoError(t, err, "unable to connect to the doom port-forward")

	// Check that 'curl' returns something.
	// Right now we're just checking that `curl` returns 0. It can be enhanced by scraping the HTML that gets returned or something.
	resp, err := http.Get("http://127.0.0.1:22333?doom")
	assert.NoError(t, err, resp)
	assert.Equal(t, 200, resp.StatusCode)

	// Clean up after this test (incase other tests cases will be run afterwards)
	e2e.cleanupAfterTest(t)
}
