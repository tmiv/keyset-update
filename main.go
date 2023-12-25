package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	sm "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	smpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/golang-collections/collections/set"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/rs/cors"
	"github.com/xenitab/go-oidc-middleware/oidctoken"
	"github.com/xenitab/go-oidc-middleware/options"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func update(w http.ResponseWriter, r *http.Request) {
	c, secret_name, project_name, err := createEssentials(r.Context())
	if err != nil {
		log.Printf("Create Essentials %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer c.Close()
	prevPayload, err := getSecret(r.Context(), secret_name, project_name, c)
	if err != nil {
		log.Printf("Prev Secret %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	prevSet, err := jwk.Parse(prevPayload)
	if err != nil {
		log.Printf("Parse Prev Secret %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	addNewKeyToKeyset(r.Context(), prevSet)
	payload, err := json.Marshal(prevSet)
	if err != nil {
		log.Printf("Set Marshal %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = writeSecretVersion(r.Context(), secret_name, project_name, payload, c)
	if err != nil {
		log.Printf("Could not create secret version %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func setupcors() *cors.Cors {
	options := cors.Options{
		AllowedMethods:   []string{http.MethodPost},
		AllowCredentials: true,
		AllowedHeaders:   []string{"Authorization"},
	}
	originsenv := os.Getenv("CORS_ORIGINS")
	if len(originsenv) > 0 {
		origins := strings.Split(originsenv, "'")
		options.AllowedOrigins = origins
	}
	return cors.New(options)
}

func makeSymmRawKey(key jwk.SymmetricKey) error {
	rawkey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rawkey); err != nil {
		return err
	}
	err := key.FromRaw(rawkey)
	if err != nil {
		return err
	}
	return nil
}

func addNewKeyToKeyset(ctx context.Context, set jwk.Set) {
	for set.Len() > 1 {
		it := set.Iterate(ctx)
		it.Next(ctx)
		pair := it.Pair()
		key := pair.Value.(jwk.Key)
		set.Remove(key)
	}
	key := jwk.NewSymmetricKey()
	key.Set("kid", uuid.NewString())
	makeSymmRawKey(key)
	set.Add(key)
}

func create(w http.ResponseWriter, r *http.Request) {
	set := jwk.NewSet()
	addNewKeyToKeyset(r.Context(), set)
	addNewKeyToKeyset(r.Context(), set)
	payload, err := json.Marshal(set)
	if err != nil {
		log.Fatalf("Bad news %v\n", err)
	}

	c, secret_name, project_name, err := createEssentials(r.Context())
	if err != nil {
		log.Printf("Create Essentials %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer c.Close()

	getsecretreq := smpb.GetSecretRequest{
		Name: "projects/" + project_name + "/secrets/" + secret_name,
	}
	activesecret, err := c.GetSecret(r.Context(), &getsecretreq)
	if err != nil {
		if status.Code(err) != codes.NotFound {
			log.Printf("Could not get secret %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	if activesecret == nil {
		activesecret, err = createSecret(r.Context(), secret_name, project_name, c)
		if activesecret == nil || err != nil {
			log.Printf("Could not create secret %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
	err = writeSecretVersion(r.Context(), secret_name, project_name, payload, c)
	if err != nil {
		log.Printf("Could not create secret version %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func createEssentials(ctx context.Context) (*sm.Client, string, string, error) {
	c, err := sm.NewClient(ctx)
	if err != nil {
		return nil, "", "", fmt.Errorf("Error creating secret manager client %v\n", err)
	}
	secret_name := os.Getenv("SECRET_NAME")
	if len(secret_name) < 1 {
		c.Close()
		return nil, "", "", fmt.Errorf("no SECRET_NAME was delared")
	}
	project_name := os.Getenv("PROJECT_NAME")
	if len(secret_name) < 1 {
		c.Close()
		return nil, "", "", fmt.Errorf("no PROJECT_NAME was delared")
	}
	return c, secret_name, project_name, nil
}

func writeSecretVersion(ctx context.Context, secret_name string, project_name string, payload []byte, c *sm.Client) error {
	crc32c := crc32.MakeTable(crc32.Castagnoli)
	checksum := int64(crc32.Checksum(payload, crc32c))

	req := &smpb.AddSecretVersionRequest{
		Parent: "projects/" + project_name + "/secrets/" + secret_name,
		Payload: &smpb.SecretPayload{
			Data:       payload,
			DataCrc32C: &checksum,
		},
	}

	_, err := c.AddSecretVersion(ctx, req)
	return err
}

func getSecret(ctx context.Context, secret_name string, project_name string, c *sm.Client) ([]byte, error) {
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: "projects/" + project_name + "/secrets/" + secret_name + "/versions/latest",
	}

	result, err := c.AccessSecretVersion(ctx, req)
	if err != nil {
		return nil, err
	}

	// Verify the data checksum.
	crc32c := crc32.MakeTable(crc32.Castagnoli)
	checksum := int64(crc32.Checksum(result.Payload.Data, crc32c))
	if checksum != *result.Payload.DataCrc32C {
		return nil, fmt.Errorf("Data corruption detected.")
	}

	return result.Payload.Data, nil
}

func createSecret(ctx context.Context, secret_name string, project_name string, c *sm.Client) (*smpb.Secret, error) {
	createreq := smpb.CreateSecretRequest{
		SecretId: secret_name,
		Parent:   "projects/" + project_name,
		Secret: &smpb.Secret{
			Replication: &smpb.Replication{
				Replication: &smpb.Replication_Automatic_{
					Automatic: &smpb.Replication_Automatic{},
				},
			},
		},
	}
	activesecret, err := c.CreateSecret(ctx, &createreq)
	if err != nil {
		return nil, err
	}
	return activesecret, nil
}

type EmailClaims struct {
	Email string `json:"email"`
}

func emailAllowedValidator() options.ClaimsValidationFn[EmailClaims] {
	allow_env := strings.Split(os.Getenv("SECURITY_ALLOW"), ",")
	allow_list := set.New()
	for _, s := range allow_env {
		allow_list.Insert(s)
	}
	return func(claims *EmailClaims) error {
		if allow_list.Has(claims.Email) {
			return nil
		} else {
			return fmt.Errorf("%s is not on the allow list", claims.Email)
		}
	}
}

func main() {
	oidctok, err := oidctoken.New[EmailClaims](
		emailAllowedValidator(),
		options.WithIssuer(os.Getenv("SECURITY_ISSUER")),
		options.WithRequiredTokenType("JWT"),
		options.WithRequiredAudience(os.Getenv("SECURITY_AUDIENCE")),
	)
	if err != nil {
		log.Fatalf("Error creating token parser %+v\n", err)
	}
	oidcmiddle := func(next func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				fmt.Printf("No bearer %s\n", auth)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, err = oidctok.ParseToken(r.Context(), auth[7:])
			if err != nil {
				fmt.Printf("Unauthorized %v\n", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/Update", oidcmiddle(update))
	mux.HandleFunc("/v1/Create", oidcmiddle(create))
	corsobj := setupcors()
	handler := corsobj.Handler(mux)
	http.ListenAndServe("0.0.0.0:8080", handler)
}
