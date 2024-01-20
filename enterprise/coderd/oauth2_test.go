package coderd_test

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/coder/coder/v2/coderd/coderdtest"
	"github.com/coder/coder/v2/coderd/coderdtest/oidctest"
	"github.com/coder/coder/v2/coderd/httpmw"
	"github.com/coder/coder/v2/coderd/util/ptr"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/coder/v2/enterprise/coderd/coderdenttest"
	"github.com/coder/coder/v2/enterprise/coderd/license"
	"github.com/coder/coder/v2/testutil"
)

func TestOAuth2ProviderApps(t *testing.T) {
	t.Parallel()

	t.Run("Validation", func(t *testing.T) {
		t.Parallel()

		client, _ := coderdenttest.New(t, &coderdenttest.Options{LicenseOptions: &coderdenttest.LicenseOptions{
			Features: license.Features{
				codersdk.FeatureOAuth2Provider: 1,
			},
		}})

		ctx := testutil.Context(t, testutil.WaitLong)

		tests := []struct {
			name string
			req  codersdk.PostOAuth2ProviderAppRequest
		}{
			{
				name: "NameMissing",
				req: codersdk.PostOAuth2ProviderAppRequest{
					CallbackURL: "http://localhost:3000",
				},
			},
			{
				name: "NameSpaces",
				req: codersdk.PostOAuth2ProviderAppRequest{
					Name:        "foo bar",
					CallbackURL: "http://localhost:3000",
				},
			},
			{
				name: "NameTooLong",
				req: codersdk.PostOAuth2ProviderAppRequest{
					Name:        "too loooooooooooooooooooooooooong",
					CallbackURL: "http://localhost:3000",
				},
			},
			{
				name: "NameTaken",
				req: codersdk.PostOAuth2ProviderAppRequest{
					Name:        "taken",
					CallbackURL: "http://localhost:3000",
				},
			},
			{
				name: "URLMissing",
				req: codersdk.PostOAuth2ProviderAppRequest{
					Name: "foo",
				},
			},
			{
				name: "URLLocalhostNoScheme",
				req: codersdk.PostOAuth2ProviderAppRequest{
					Name:        "foo",
					CallbackURL: "localhost:3000",
				},
			},
			{
				name: "URLNoScheme",
				req: codersdk.PostOAuth2ProviderAppRequest{
					Name:        "foo",
					CallbackURL: "coder.com",
				},
			},
			{
				name: "URLNoColon",
				req: codersdk.PostOAuth2ProviderAppRequest{
					Name:        "foo",
					CallbackURL: "http//coder",
				},
			},
			{
				name: "URLJustBar",
				req: codersdk.PostOAuth2ProviderAppRequest{
					Name:        "foo",
					CallbackURL: "bar",
				},
			},
			{
				name: "URLPathOnly",
				req: codersdk.PostOAuth2ProviderAppRequest{
					Name:        "foo",
					CallbackURL: "/bar/baz/qux",
				},
			},
			{
				name: "URLJustHttp",
				req: codersdk.PostOAuth2ProviderAppRequest{
					Name:        "foo",
					CallbackURL: "http",
				},
			},
			{
				name: "URLNoHost",
				req: codersdk.PostOAuth2ProviderAppRequest{
					Name:        "foo",
					CallbackURL: "http://",
				},
			},
			{
				name: "URLSpaces",
				req: codersdk.PostOAuth2ProviderAppRequest{
					Name:        "foo",
					CallbackURL: "bar baz qux",
				},
			},
		}

		// Generate an application for testing name conflicts.
		req := codersdk.PostOAuth2ProviderAppRequest{
			Name:        "taken",
			CallbackURL: "http://coder.com",
		}
		//nolint:gocritic // OAauth2 app management requires owner permission.
		_, err := client.PostOAuth2ProviderApp(ctx, req)
		require.NoError(t, err)

		// Generate an application for testing PUTs.
		req = codersdk.PostOAuth2ProviderAppRequest{
			Name:        "quark",
			CallbackURL: "http://coder.com",
		}
		//nolint:gocritic // OAauth2 app management requires owner permission.
		existingApp, err := client.PostOAuth2ProviderApp(ctx, req)
		require.NoError(t, err)

		for _, test := range tests {
			test := test
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				//nolint:gocritic // OAauth2 app management requires owner permission.
				_, err := client.PostOAuth2ProviderApp(ctx, test.req)
				require.Error(t, err)

				//nolint:gocritic // OAauth2 app management requires owner permission.
				_, err = client.PutOAuth2ProviderApp(ctx, existingApp.ID, codersdk.PutOAuth2ProviderAppRequest{
					Name:        test.req.Name,
					CallbackURL: test.req.CallbackURL,
				})
				require.Error(t, err)
			})
		}
	})

	t.Run("DeleteNonExisting", func(t *testing.T) {
		t.Parallel()

		client, owner := coderdenttest.New(t, &coderdenttest.Options{LicenseOptions: &coderdenttest.LicenseOptions{
			Features: license.Features{
				codersdk.FeatureOAuth2Provider: 1,
			},
		}})
		another, _ := coderdtest.CreateAnotherUser(t, client, owner.OrganizationID)

		ctx := testutil.Context(t, testutil.WaitLong)

		_, err := another.OAuth2ProviderApp(ctx, uuid.New())
		require.Error(t, err)
	})

	t.Run("OK", func(t *testing.T) {
		t.Parallel()

		client, owner := coderdenttest.New(t, &coderdenttest.Options{LicenseOptions: &coderdenttest.LicenseOptions{
			Features: license.Features{
				codersdk.FeatureOAuth2Provider: 1,
			},
		}})
		another, _ := coderdtest.CreateAnotherUser(t, client, owner.OrganizationID)

		ctx := testutil.Context(t, testutil.WaitLong)

		// No apps yet.
		apps, err := another.OAuth2ProviderApps(ctx, codersdk.OAuth2ProviderAppFilter{})
		require.NoError(t, err)
		require.Len(t, apps, 0)

		// Should be able to add apps.
		expected := generateApps(ctx, t, client)
		expectedOrder := []codersdk.OAuth2ProviderApp{
			expected.Default, expected.NoPort, expected.Subdomain,
			expected.Extra[0], expected.Extra[1],
		}

		// Should get all the apps now.
		apps, err = another.OAuth2ProviderApps(ctx, codersdk.OAuth2ProviderAppFilter{})
		require.NoError(t, err)
		require.Len(t, apps, 5)
		require.Equal(t, expectedOrder, apps)

		// Should be able to keep the same name when updating.
		req := codersdk.PutOAuth2ProviderAppRequest{
			Name:        expected.Default.Name,
			CallbackURL: "http://coder.com",
			Icon:        "test",
		}
		//nolint:gocritic // OAauth2 app management requires owner permission.
		newApp, err := client.PutOAuth2ProviderApp(ctx, expected.Default.ID, req)
		require.NoError(t, err)
		require.Equal(t, req.Name, newApp.Name)
		require.Equal(t, req.CallbackURL, newApp.CallbackURL)
		require.Equal(t, req.Icon, newApp.Icon)
		require.Equal(t, expected.Default.ID, newApp.ID)

		// Should be able to update name.
		req = codersdk.PutOAuth2ProviderAppRequest{
			Name:        "new-foo",
			CallbackURL: "http://coder.com",
			Icon:        "test",
		}
		//nolint:gocritic // OAauth2 app management requires owner permission.
		newApp, err = client.PutOAuth2ProviderApp(ctx, expected.Default.ID, req)
		require.NoError(t, err)
		require.Equal(t, req.Name, newApp.Name)
		require.Equal(t, req.CallbackURL, newApp.CallbackURL)
		require.Equal(t, req.Icon, newApp.Icon)
		require.Equal(t, expected.Default.ID, newApp.ID)

		// Should be able to get a single app.
		got, err := another.OAuth2ProviderApp(ctx, expected.Default.ID)
		require.NoError(t, err)
		require.Equal(t, newApp, got)

		// Should be able to delete an app.
		//nolint:gocritic // OAauth2 app management requires owner permission.
		err = client.DeleteOAuth2ProviderApp(ctx, expected.Default.ID)
		require.NoError(t, err)

		// Should show the new count.
		newApps, err := another.OAuth2ProviderApps(ctx, codersdk.OAuth2ProviderAppFilter{})
		require.NoError(t, err)
		require.Len(t, newApps, 4)

		require.Equal(t, expectedOrder[1:], newApps)
	})

	t.Run("ByUser", func(t *testing.T) {
		t.Parallel()
		client, owner := coderdenttest.New(t, &coderdenttest.Options{LicenseOptions: &coderdenttest.LicenseOptions{
			Features: license.Features{
				codersdk.FeatureOAuth2Provider: 1,
			},
		}})
		another, user := coderdtest.CreateAnotherUser(t, client, owner.OrganizationID)
		ctx := testutil.Context(t, testutil.WaitLong)
		_ = generateApps(ctx, t, client)
		apps, err := another.OAuth2ProviderApps(ctx, codersdk.OAuth2ProviderAppFilter{
			UserID: user.ID,
		})
		require.NoError(t, err)
		require.Len(t, apps, 0)
	})
}

func TestOAuth2ProviderAppSecrets(t *testing.T) {
	t.Parallel()

	client, _ := coderdenttest.New(t, &coderdenttest.Options{LicenseOptions: &coderdenttest.LicenseOptions{
		Features: license.Features{
			codersdk.FeatureOAuth2Provider: 1,
		},
	}})

	ctx := testutil.Context(t, testutil.WaitLong)

	// Make some apps.
	//nolint:gocritic // OAauth2 app management requires owner permission.
	app1, err := client.PostOAuth2ProviderApp(ctx, codersdk.PostOAuth2ProviderAppRequest{
		Name:        "razzle-dazzle",
		CallbackURL: "http://localhost",
	})
	require.NoError(t, err)

	//nolint:gocritic // OAauth2 app management requires owner permission.
	app2, err := client.PostOAuth2ProviderApp(ctx, codersdk.PostOAuth2ProviderAppRequest{
		Name:        "razzle-dazzle-the-sequel",
		CallbackURL: "http://localhost",
	})
	require.NoError(t, err)

	t.Run("DeleteNonExisting", func(t *testing.T) {
		t.Parallel()

		// Should not be able to create secrets for a non-existent app.
		//nolint:gocritic // OAauth2 app management requires owner permission.
		_, err = client.OAuth2ProviderAppSecrets(ctx, uuid.New())
		require.Error(t, err)

		// Should not be able to delete non-existing secrets when there is no app.
		//nolint:gocritic // OAauth2 app management requires owner permission.
		err = client.DeleteOAuth2ProviderAppSecret(ctx, uuid.New(), uuid.New())
		require.Error(t, err)

		// Should not be able to delete non-existing secrets when the app exists.
		//nolint:gocritic // OAauth2 app management requires owner permission.
		err = client.DeleteOAuth2ProviderAppSecret(ctx, app1.ID, uuid.New())
		require.Error(t, err)

		// Should not be able to delete an existing secret with the wrong app ID.
		//nolint:gocritic // OAauth2 app management requires owner permission.
		secret, err := client.PostOAuth2ProviderAppSecret(ctx, app2.ID)
		require.NoError(t, err)

		//nolint:gocritic // OAauth2 app management requires owner permission.
		err = client.DeleteOAuth2ProviderAppSecret(ctx, app1.ID, secret.ID)
		require.Error(t, err)
	})

	t.Run("OK", func(t *testing.T) {
		t.Parallel()

		// No secrets yet.
		//nolint:gocritic // OAauth2 app management requires owner permission.
		secrets, err := client.OAuth2ProviderAppSecrets(ctx, app1.ID)
		require.NoError(t, err)
		require.Len(t, secrets, 0)

		// Should be able to create secrets.
		for i := 0; i < 5; i++ {
			//nolint:gocritic // OAauth2 app management requires owner permission.
			secret, err := client.PostOAuth2ProviderAppSecret(ctx, app1.ID)
			require.NoError(t, err)
			require.NotEmpty(t, secret.ClientSecretFull)
			require.True(t, len(secret.ClientSecretFull) > 6)

			//nolint:gocritic // OAauth2 app management requires owner permission.
			_, err = client.PostOAuth2ProviderAppSecret(ctx, app2.ID)
			require.NoError(t, err)
		}

		// Should get secrets now, but only for the one app.
		//nolint:gocritic // OAauth2 app management requires owner permission.
		secrets, err = client.OAuth2ProviderAppSecrets(ctx, app1.ID)
		require.NoError(t, err)
		require.Len(t, secrets, 5)
		for _, secret := range secrets {
			require.Len(t, secret.ClientSecretTruncated, 6)
		}

		// Should be able to delete a secret.
		//nolint:gocritic // OAauth2 app management requires owner permission.
		err = client.DeleteOAuth2ProviderAppSecret(ctx, app1.ID, secrets[0].ID)
		require.NoError(t, err)
		secrets, err = client.OAuth2ProviderAppSecrets(ctx, app1.ID)
		require.NoError(t, err)
		require.Len(t, secrets, 4)

		// No secrets once the app is deleted.
		//nolint:gocritic // OAauth2 app management requires owner permission.
		err = client.DeleteOAuth2ProviderApp(ctx, app1.ID)
		require.NoError(t, err)

		//nolint:gocritic // OAauth2 app management requires owner permission.
		_, err = client.OAuth2ProviderAppSecrets(ctx, app1.ID)
		require.Error(t, err)
	})
}

func TestOAuth2ProviderTokenExchange(t *testing.T) {
	t.Parallel()

	ownerClient, owner := coderdenttest.New(t, &coderdenttest.Options{LicenseOptions: &coderdenttest.LicenseOptions{
		Features: license.Features{
			codersdk.FeatureOAuth2Provider: 1,
		},
	}})
	userClient, _ := coderdtest.CreateAnotherUser(t, ownerClient, owner.OrganizationID)
	ctx := testutil.Context(t, testutil.WaitLong)
	apps := generateApps(ctx, t, ownerClient)

	//nolint:gocritic // OAauth2 app management requires owner permission.
	secret, err := ownerClient.PostOAuth2ProviderAppSecret(ctx, apps.Default.ID)
	require.NoError(t, err)

	// The typical oauth2 flow from this point is:
	// Create an oauth2.Config using the id, secret, endpoints, and redirect:
	//	cfg := oauth2.Config{ ... }
	// Display url for the user to click:
	//	userClickURL := cfg.AuthCodeURL("random_state")
	//	userClickURL looks like: https://idp url/authorize?
	//								client_id=...
	//								response_type=code
	//								redirect_uri=.. (back to backstage url) ..
	//								scope=...
	//								state=...
	// *1* User clicks "Allow" on provided page above
	// The redirect_uri is followed which sends back to backstage with the code and state
	// Now backstage has the info to do a cfg.Exchange() in the back to get an access token.
	//
	// ---NOTE---: If the user has already approved this oauth app, then *1* is optional.
	//             Coder can just immediately redirect back to backstage without user intervention.
	tests := []struct {
		name string
		app  codersdk.OAuth2ProviderApp
		// The flow is preAuth(cfg) -> cfg.AuthCodeURL() -> preToken(cfg) -> cfg.Exchange()
		preAuth    func(valid *oauth2.Config)
		authError  string
		preToken   func(valid *oauth2.Config)
		tokenError string

		// If null, assume the code should be valid.
		defaultCode *string
		// custom allows some more advanced manipulation of the oauth2 exchange.
		exchangeMutate []oauth2.AuthCodeOption
	}{
		{
			name: "AuthInParams",
			app:  apps.Default,
			preAuth: func(valid *oauth2.Config) {
				valid.Endpoint.AuthStyle = oauth2.AuthStyleInParams
			},
		},
		{
			name: "AuthInvalidAppID",
			app:  apps.Default,
			preAuth: func(valid *oauth2.Config) {
				valid.ClientID = uuid.NewString()
			},
			authError: "Resource not found",
		},
		{
			name: "TokenInvalidAppID",
			app:  apps.Default,
			preToken: func(valid *oauth2.Config) {
				valid.ClientID = uuid.NewString()
			},
			tokenError: "Resource not found",
		},
		{
			name: "InvalidPort",
			app:  apps.NoPort,
			preAuth: func(valid *oauth2.Config) {
				newURL := must(url.Parse(valid.RedirectURL))
				newURL.Host = newURL.Hostname() + ":8081"
				valid.RedirectURL = newURL.String()
			},
			authError: "Invalid redirect URL",
		},
		{
			name: "WrongAppHost",
			app:  apps.Default,
			preAuth: func(valid *oauth2.Config) {
				valid.RedirectURL = apps.NoPort.CallbackURL
			},
			authError: "Invalid redirect URL",
		},
		{
			name: "InvalidHostPrefix",
			app:  apps.NoPort,
			preAuth: func(valid *oauth2.Config) {
				newURL := must(url.Parse(valid.RedirectURL))
				newURL.Host = "prefix" + newURL.Hostname()
				valid.RedirectURL = newURL.String()
			},
			authError: "Invalid redirect URL",
		},
		{
			name: "InvalidHost",
			app:  apps.NoPort,
			preAuth: func(valid *oauth2.Config) {
				newURL := must(url.Parse(valid.RedirectURL))
				newURL.Host = "invalid"
				valid.RedirectURL = newURL.String()
			},
			authError: "Invalid redirect URL",
		},
		{
			name: "InvalidHostAndPort",
			app:  apps.NoPort,
			preAuth: func(valid *oauth2.Config) {
				newURL := must(url.Parse(valid.RedirectURL))
				newURL.Host = "invalid:8080"
				valid.RedirectURL = newURL.String()
			},
			authError: "Invalid redirect URL",
		},
		{
			name: "InvalidPath",
			app:  apps.Default,
			preAuth: func(valid *oauth2.Config) {
				newURL := must(url.Parse(valid.RedirectURL))
				newURL.Path = filepath.Join("/prepend", newURL.Path)
				valid.RedirectURL = newURL.String()
			},
			authError: "Invalid redirect URL",
		},
		{
			name: "MissingPath",
			app:  apps.Default,
			preAuth: func(valid *oauth2.Config) {
				newURL := must(url.Parse(valid.RedirectURL))
				newURL.Path = "/"
				valid.RedirectURL = newURL.String()
			},
			authError: "Invalid redirect URL",
		},
		{
			// Should this work?
			name: "DifferentProtocol",
			app:  apps.Default,
			preAuth: func(valid *oauth2.Config) {
				newURL := must(url.Parse(valid.RedirectURL))
				newURL.Scheme = "https"
				valid.RedirectURL = newURL.String()
			},
		},
		{
			name: "NestedPath",
			app:  apps.Default,
			preAuth: func(valid *oauth2.Config) {
				newURL := must(url.Parse(valid.RedirectURL))
				newURL.Path = filepath.Join(newURL.Path, "nested")
				valid.RedirectURL = newURL.String()
			},
		},
		{
			// Some oauth implementations allow this, but our users can host
			// at subdomains. So we should not.
			name: "Subdomain",
			app:  apps.Default,
			preAuth: func(valid *oauth2.Config) {
				newURL := must(url.Parse(valid.RedirectURL))
				newURL.Host = "sub." + newURL.Host
				valid.RedirectURL = newURL.String()
			},
			authError: "Invalid redirect URL",
		},
		{
			name: "InvalidSecret",
			app:  apps.Default,
			preToken: func(valid *oauth2.Config) {
				valid.ClientSecret = uuid.NewString()
			},
			tokenError: "Invalid client secret or code",
		},
		{
			name: "MissingSecret",
			app:  apps.Default,
			preToken: func(valid *oauth2.Config) {
				valid.ClientSecret = ""
			},
			tokenError: "Invalid query params",
		},
		{
			name:        "InvalidCode",
			app:         apps.Default,
			defaultCode: ptr.Ref(uuid.NewString()),
			tokenError:  "Invalid client secret or code",
		},
		{
			name:        "MissingCode",
			app:         apps.Default,
			defaultCode: ptr.Ref(""),
			tokenError:  "Invalid client secret or code",
		},
		{
			name: "OK",
			app:  apps.Default,
		},
		{
			name:       "InvalidGrantType",
			app:        apps.Default,
			tokenError: "Unsupported grant type",
			exchangeMutate: []oauth2.AuthCodeOption{
				oauth2.SetAuthURLParam("grant_type", "foobar"),
			},
		},
		{
			name:       "EmptyGrantType",
			app:        apps.Default,
			tokenError: "Unsupported grant type",
			exchangeMutate: []oauth2.AuthCodeOption{
				oauth2.SetAuthURLParam("grant_type", ""),
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// Each test gets its own oauth2.Config so they can run in parallel.
			// In practice, you would only use 1 as a singleton.
			valid := &oauth2.Config{
				ClientID:     test.app.ID.String(),
				ClientSecret: secret.ClientSecretFull,
				Endpoint: oauth2.Endpoint{
					AuthURL:       test.app.Endpoints.Authorization,
					DeviceAuthURL: test.app.Endpoints.DeviceAuth,
					TokenURL:      test.app.Endpoints.Token,
					// TODO: @emyrk we should support both types.
					AuthStyle: oauth2.AuthStyleInParams,
				},
				RedirectURL: test.app.CallbackURL,
				Scopes:      []string{},
			}

			ctx := testutil.Context(t, testutil.WaitLong)

			if test.preAuth != nil {
				test.preAuth(valid)
			}

			var code string
			if test.defaultCode != nil {
				code = *test.defaultCode
			} else {
				code, err = authorizationFlow(userClient, valid)
				if test.authError != "" {
					require.Error(t, err)
					require.ErrorContains(t, err, test.authError)
					// If this errors the token exchange will fail. So end here.
					return
				}
				require.NoError(t, err)
			}

			// Mutate the valid config for the exchange.
			if test.preToken != nil {
				test.preToken(valid)
			}

			token, err := valid.Exchange(ctx, code, test.exchangeMutate...)
			if test.tokenError != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, test.tokenError)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, token.AccessToken)
			}
		})
	}
}

type exchangeSetup struct {
	cfg    *oauth2.Config
	app    codersdk.OAuth2ProviderApp
	secret codersdk.OAuth2ProviderAppSecretFull
	code   string
}

func TestOAuth2ProviderRevoke(t *testing.T) {
	t.Parallel()

	client, owner := coderdenttest.New(t, &coderdenttest.Options{LicenseOptions: &coderdenttest.LicenseOptions{
		Features: license.Features{
			codersdk.FeatureOAuth2Provider: 1,
		},
	}})

	tests := []struct {
		name string
		fn   func(context.Context, *codersdk.Client, exchangeSetup)
	}{
		{
			name: "DeleteApp",
			fn: func(ctx context.Context, _ *codersdk.Client, s exchangeSetup) {
				//nolint:gocritic // OAauth2 app management requires owner permission.
				err := client.DeleteOAuth2ProviderApp(ctx, s.app.ID)
				require.NoError(t, err)
			},
		},
		{
			name: "DeleteSecret",
			fn: func(ctx context.Context, _ *codersdk.Client, s exchangeSetup) {
				//nolint:gocritic // OAauth2 app management requires owner permission.
				err := client.DeleteOAuth2ProviderAppSecret(ctx, s.app.ID, s.secret.ID)
				require.NoError(t, err)
			},
		},
		{
			name: "DeleteToken",
			fn: func(ctx context.Context, client *codersdk.Client, s exchangeSetup) {
				err := client.RevokeOAuth2ProviderApp(ctx, s.app.ID)
				require.NoError(t, err)
			},
		},
	}

	setup := func(ctx context.Context, testClient *codersdk.Client, name string) exchangeSetup {
		//nolint:gocritic // OAauth2 app management requires owner permission.
		app, err := client.PostOAuth2ProviderApp(ctx, codersdk.PostOAuth2ProviderAppRequest{
			Name:        name,
			CallbackURL: "http://localhost",
		})
		require.NoError(t, err)

		//nolint:gocritic // OAauth2 app management requires owner permission.
		secret, err := client.PostOAuth2ProviderAppSecret(ctx, app.ID)
		require.NoError(t, err)

		cfg := &oauth2.Config{
			ClientID:     app.ID.String(),
			ClientSecret: secret.ClientSecretFull,
			Endpoint: oauth2.Endpoint{
				AuthURL:       app.Endpoints.Authorization,
				DeviceAuthURL: app.Endpoints.DeviceAuth,
				TokenURL:      app.Endpoints.Token,
				AuthStyle:     oauth2.AuthStyleInParams,
			},
			RedirectURL: app.CallbackURL,
			Scopes:      []string{},
		}

		code, err := authorizationFlow(testClient, cfg)
		require.NoError(t, err)

		return exchangeSetup{
			cfg:    cfg,
			app:    app,
			secret: secret,
			code:   code,
		}
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := testutil.Context(t, testutil.WaitLong)
			testClient, testUser := coderdtest.CreateAnotherUser(t, client, owner.OrganizationID)

			testEntities := setup(ctx, testClient, test.name+"-1")

			// Delete before the exchange completes (code should delete and attempting
			// to finish the exchange should fail).
			test.fn(ctx, testClient, testEntities)

			// Exchange should fail because the code should be gone.

			_, err := testEntities.cfg.Exchange(ctx, testEntities.code)
			require.Error(t, err)

			// Try again, this time letting the exchange complete first.
			testEntities = setup(ctx, testClient, test.name+"-2")
			token, err := testEntities.cfg.Exchange(ctx, testEntities.code)
			require.NoError(t, err)

			// Validate the returned access token and that the app is listed.
			newClient := codersdk.New(client.URL)
			newClient.SetSessionToken(token.AccessToken)

			gotUser, err := newClient.User(ctx, codersdk.Me)
			require.NoError(t, err)
			require.Equal(t, testUser.ID, gotUser.ID)

			filter := codersdk.OAuth2ProviderAppFilter{UserID: testUser.ID}
			apps, err := testClient.OAuth2ProviderApps(ctx, filter)
			require.NoError(t, err)
			require.Contains(t, apps, testEntities.app)

			// Should not show up for another user.
			apps, err = client.OAuth2ProviderApps(ctx, codersdk.OAuth2ProviderAppFilter{UserID: owner.UserID})
			require.NoError(t, err)
			require.Len(t, apps, 0)

			// Perform the deletion.
			test.fn(ctx, testClient, testEntities)

			// App should no longer show up for the user and the token should no
			// longer be valid.
			apps, err = testClient.OAuth2ProviderApps(ctx, filter)
			require.NoError(t, err)
			require.NotContains(t, apps, testEntities.app)

			_, err = newClient.User(ctx, codersdk.Me)
			require.Error(t, err)
			require.ErrorContains(t, err, "401")
		})
	}
}

type provisionedApps struct {
	Default   codersdk.OAuth2ProviderApp
	NoPort    codersdk.OAuth2ProviderApp
	Subdomain codersdk.OAuth2ProviderApp
	// For sorting purposes these are included. You will likely never touch them.
	Extra []codersdk.OAuth2ProviderApp
}

func generateApps(ctx context.Context, t *testing.T, client *codersdk.Client) provisionedApps {
	create := func(name, callback string) codersdk.OAuth2ProviderApp {
		//nolint:gocritic // OAauth2 app management requires owner permission.
		app, err := client.PostOAuth2ProviderApp(ctx, codersdk.PostOAuth2ProviderAppRequest{
			Name:        name,
			CallbackURL: callback,
			Icon:        "",
		})
		require.NoError(t, err)
		require.Equal(t, name, app.Name)
		require.Equal(t, callback, app.CallbackURL)
		return app
	}

	return provisionedApps{
		Default:   create("razzle-dazzle", "http://localhost1:8080/foo/bar"),
		NoPort:    create("razzle-dazzle-the-sequel", "http://localhost2"),
		Subdomain: create("razzle-dazzle-the-z-prequel", "http://30.localhost:3000"),
		Extra: []codersdk.OAuth2ProviderApp{
			create("the-not-really-twenty", "http://20.localhost:3000"),
			create("woo-10", "http://10.localhost:3000"),
		},
	}
}

func authorizationFlow(client *codersdk.Client, cfg *oauth2.Config) (string, error) {
	state := uuid.NewString()
	return oidctest.OAuth2GetCode(
		cfg.AuthCodeURL(state),
		state,
		func(req *http.Request) (*http.Response, error) {
			// TODO: Would be better if client had a .Do() method.
			// TODO: Is this the best way to handle redirects?
			client.HTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
			return client.Request(context.Background(), req.Method, req.URL.String(), nil, func(req *http.Request) {
				// Including the path here is ok.
				req.Header.Set(httpmw.OriginHeader, client.URL.String())
				req.Header.Set("Referer", client.URL.String())
			})
		},
	)
}
