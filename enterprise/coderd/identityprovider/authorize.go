package identityprovider

import (
	"crypto/sha256"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/xerrors"

	"github.com/coder/coder/v2/coderd/database"
	"github.com/coder/coder/v2/coderd/database/dbtime"
	"github.com/coder/coder/v2/coderd/httpapi"
	"github.com/coder/coder/v2/coderd/httpmw"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/coder/v2/cryptorand"
)

/**
 * Authorize displays an HTML for authorizing an application when the user has
 * first been redirected to this path and generates a code and redirects to the
 * app's callback URL after the user clicks "allow" on that page.
 */
func Authorize(db database.Store, accessURL *url.URL) http.HandlerFunc {
	handler := func(rw http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		apiKey, ok := httpmw.APIKeyOptional(r)
		if !ok {
			// TODO: Should this be unauthorized? Or Forbidden?
			// This should redirect to a login page.
			httpapi.Forbidden(rw)
			return
		}

		app := httpmw.OAuth2ProviderApp(r)

		// TODO: @emyrk this should always work, maybe make callbackURL a *url.URL?
		callbackURL, _ := url.Parse(app.CallbackURL)

		// TODO: Should validate these on the HTML page as well and show errors
		// there rather than wait until this endpoint to show them.
		p := httpapi.NewQueryParamParser()
		vals := r.URL.Query()
		p.Required("state", "response_type")
		state := p.String(vals, "", "state")
		scope := p.Strings(vals, []string{}, "scope")
		// Client_id is already parsed in the mw above.
		_ = p.String(vals, "", "client_id")
		redirectURL := p.URL(vals, callbackURL, "redirect_uri")
		responseType := p.String(vals, "", "response_type")
		// TODO: Redirected might exist but it should not cause validation errors.
		_ = p.String(vals, "", "redirected")
		p.ErrorExcessParams(vals)
		if len(p.Errors) > 0 {
			httpapi.Write(ctx, rw, http.StatusBadRequest, codersdk.Response{
				Message:     "Invalid query params.",
				Validations: p.Errors,
			})
			return
		}

		// TODO: @emyrk what other ones are there?
		if responseType != "code" {
			httpapi.Write(ctx, rw, http.StatusBadRequest, codersdk.Response{
				Message: "Invalid response type.",
			})
			return
		}

		// TODO: @emyrk handle scope?
		_ = scope

		if err := validateRedirectURL(app.CallbackURL, redirectURL.String()); err != nil {
			httpapi.Write(r.Context(), rw, http.StatusBadRequest, codersdk.Response{
				Message: "Invalid redirect URL.",
			})
			return
		}
		// 40 characters matches the length of GitHub's client secrets.
		rawSecret, err := cryptorand.String(40)
		if err != nil {
			httpapi.Write(r.Context(), rw, http.StatusInternalServerError, codersdk.Response{
				Message: "Failed to generate OAuth2 app authorization code.",
			})
			return
		}
		hashed := sha256.Sum256([]byte(rawSecret))
		_, err = db.InsertOAuth2ProviderAppCode(ctx, database.InsertOAuth2ProviderAppCodeParams{
			ID:        uuid.New(),
			CreatedAt: dbtime.Now(),
			// TODO: Configurable expiration?
			ExpiresAt:    dbtime.Now().Add(time.Duration(10) * time.Minute),
			HashedSecret: hashed[:],
			AppID:        app.ID,
			UserID:       apiKey.UserID,
		})
		if err != nil {
			httpapi.Write(ctx, rw, http.StatusInternalServerError, codersdk.Response{
				Message: "Internal error insert OAuth2 authorization code.",
				Detail:  err.Error(),
			})
			return
		}

		newQuery := redirectURL.Query()
		newQuery.Add("code", rawSecret)
		newQuery.Add("state", state)
		redirectURL.RawQuery = newQuery.Encode()

		http.Redirect(rw, r, redirectURL.String(), http.StatusTemporaryRedirect)
	}

	// Always wrap with its custom mw.
	return authorizeMW(accessURL)(http.HandlerFunc(handler)).ServeHTTP
}

// validateRedirectURL validates that the redirectURL is contained in baseURL.
func validateRedirectURL(baseURL string, redirectURL string) error {
	base, err := url.Parse(baseURL)
	if err != nil {
		return err
	}

	redirect, err := url.Parse(redirectURL)
	if err != nil {
		return err
	}
	// It can be a sub-directory but not a sub-domain, as we have apps on
	// sub-domains so it seems too dangerous.
	if redirect.Host != base.Host || !strings.HasPrefix(redirect.Path, base.Path) {
		return xerrors.New("invalid redirect URL")
	}
	return nil
}
