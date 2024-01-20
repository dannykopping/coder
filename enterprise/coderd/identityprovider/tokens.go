package identityprovider

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"

	"github.com/coder/coder/v2/coderd/apikey"
	"github.com/coder/coder/v2/coderd/database"
	"github.com/coder/coder/v2/coderd/database/dbauthz"
	"github.com/coder/coder/v2/coderd/database/dbtime"
	"github.com/coder/coder/v2/coderd/httpapi"
	"github.com/coder/coder/v2/coderd/httpmw"
	"github.com/coder/coder/v2/coderd/rbac"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/coder/v2/cryptorand"
)

func Tokens(db database.Store, defaultLifetime time.Duration) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		app := httpmw.OAuth2ProviderApp(r)
		p := httpapi.NewQueryParamParser()
		err := r.ParseForm()
		if err != nil {
			httpapi.Write(ctx, rw, http.StatusBadRequest, codersdk.Response{
				Message: "Failed to parse form.",
				Detail:  err.Error(),
			})
			return
		}
		vals := r.Form
		p.Required("grant_type", "client_secret", "client_id", "code")
		clientSecret := p.String(vals, "", "client_secret")
		// Client ID was already used in the middleware.
		_ = p.String(vals, "", "client_id")
		// TODO: Redirect URI can be included but seems to have no purpose.
		_ = p.URL(vals, nil, "redirect_uri")
		grantType := p.String(vals, "", "grant_type")
		code := p.String(vals, "", "code")
		p.ErrorExcessParams(vals)
		if len(p.Errors) > 0 {
			httpapi.Write(ctx, rw, http.StatusBadRequest, codersdk.Response{
				Message:     "Invalid query params.",
				Validations: p.Errors,
			})
			return
		}

		var token oauth2.Token
		switch codersdk.OAuth2ProviderGrantType(grantType) {
		case codersdk.OAuth2ProviderGrantTypeAuthorizationCode:
			token, err = authorizationCodeGrant(ctx, db, app, defaultLifetime, clientSecret, code)
			// TODO: Client creds, device code, refresh
		default:
			httpapi.Write(r.Context(), rw, http.StatusBadRequest, codersdk.Response{
				Message: "Unsupported grant type",
			})
			return
		}

		if err != nil && errors.Is(err, sql.ErrNoRows) {
			httpapi.Write(r.Context(), rw, http.StatusUnauthorized, codersdk.Response{
				Message: "Invalid client secret or code",
			})
			return
		}
		if err != nil {
			httpapi.Write(r.Context(), rw, http.StatusInternalServerError, codersdk.Response{
				Message: "Failed to exchange token",
				Detail:  err.Error(),
			})
			return
		}

		// Some client libraries allow this to be "application/x-www-form-urlencoded". We can implement that upon
		// request. The same libraries should also accept JSON. If implemented, choose based on "Accept" header.
		httpapi.Write(ctx, rw, http.StatusOK, token)
	}
}

func authorizationCodeGrant(ctx context.Context, db database.Store, app database.OAuth2ProviderApp, defaultLifetime time.Duration, clientSecret, code string) (oauth2.Token, error) {
	// TODO: Let's not use unsalted secrets. To be improved in next iteration.
	// 		When we add this, all existing tokens & secrets will be invalid.
	// 		They will have to be regenerated. So do before a GA release.
	// Validate the client secret.
	secretHash := sha256.Sum256([]byte(clientSecret))
	secret, err := db.GetOAuth2ProviderAppSecretByAppIDAndSecret(
		//nolint:gocritic // System needs to validate the client secret.
		dbauthz.AsSystemRestricted(ctx),
		database.GetOAuth2ProviderAppSecretByAppIDAndSecretParams{
			AppID:        app.ID,
			HashedSecret: secretHash[:],
		})
	if err != nil {
		return oauth2.Token{}, err
	}

	// Validate the authorization code.
	codeHash := sha256.Sum256([]byte(code))
	dbCode, err := db.GetOAuth2ProviderAppCodeByAppIDAndSecret(
		//nolint:gocritic // System needs to validate the code.
		dbauthz.AsSystemRestricted(ctx),
		database.GetOAuth2ProviderAppCodeByAppIDAndSecretParams{
			AppID:        app.ID,
			HashedSecret: codeHash[:],
		})
	if err != nil {
		return oauth2.Token{}, err
	}

	// Generate a refresh token.
	// The refresh token is not currently used or exposed though as API keys can
	// already be refreshed by just using them.
	// TODO: However, should we implement the refresh grant anyway?
	// 40 characters matches the length of GitHub's client secrets.
	// TODO: Probably do same hash style security here.
	rawRefreshToken, err := cryptorand.String(40)
	if err != nil {
		return oauth2.Token{}, err
	}

	// Generate the API key we will swap for the code.
	// TODO: We are ignoring scopes for now.
	// TODO: Should we add a name and only allow one at a time? (@emyrk I like that idea)
	key, sessionToken, err := apikey.Generate(apikey.CreateParams{
		UserID:    dbCode.UserID,
		LoginType: database.LoginTypeOAuth2ProviderApp,
		// TODO: This is just the lifetime for api keys, maybe have it's own config
		// settings. #11693
		DefaultLifetime: defaultLifetime,
	})
	if err != nil {
		return oauth2.Token{}, err
	}

	// Grab the user roles so we can perform the exchange as the user.
	// In the token exchange, there is no user actor.
	//nolint:gocritic // System needs to fetch user roles.
	roles, err := db.GetAuthorizationUserRoles(dbauthz.AsSystemRestricted(ctx), dbCode.UserID)
	if err != nil {
		return oauth2.Token{}, err
	}
	userSubj := rbac.Subject{
		ID:     dbCode.UserID.String(),
		Roles:  rbac.RoleNames(roles.Roles),
		Groups: roles.Groups,
		Scope:  rbac.ScopeAll,
	}

	// Do the actual token exchange in the database.
	err = db.InTx(func(tx database.Store) error {
		err = tx.DeleteOAuth2ProviderAppCodeByID(dbauthz.As(ctx, userSubj), dbCode.ID)
		if err != nil {
			return xerrors.Errorf("delete oauth2 app code: %w", err)
		}

		newKey, err := tx.InsertAPIKey(dbauthz.As(ctx, userSubj), key)
		if err != nil {
			return xerrors.Errorf("insert oauth2 access token: %w", err)
		}

		hashed := sha256.Sum256([]byte(rawRefreshToken))
		_, err = tx.InsertOAuth2ProviderAppToken(
			dbauthz.As(ctx, userSubj),
			database.InsertOAuth2ProviderAppTokenParams{
				ID:           uuid.New(),
				CreatedAt:    dbtime.Now(),
				ExpiresAt:    key.ExpiresAt,
				HashedSecret: hashed[:],
				AppSecretID:  secret.ID,
				APIKeyID:     newKey.ID,
			})
		if err != nil {
			return xerrors.Errorf("insert oauth2 refresh token: %w", err)
		}
		return nil
	}, nil)
	if err != nil {
		return oauth2.Token{}, err
	}

	return oauth2.Token{
		AccessToken:  sessionToken,
		TokenType:    "Bearer",
		RefreshToken: rawRefreshToken,
		Expiry:       key.ExpiresAt,
	}, nil
}
