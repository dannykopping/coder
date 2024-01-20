package identityprovider

import (
	"net/http"
	"net/url"

	"github.com/coder/coder/v2/coderd/httpapi"
	"github.com/coder/coder/v2/coderd/httpmw"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/coder/v2/site"
)

// authorizeMW serves to remove some code from the primary authorize handler.
// It decides when to show the html allow page, and when to just continue.
func authorizeMW(accessURL *url.URL) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get(httpmw.OriginHeader)
			originU, err := url.Parse(origin)
			if err != nil {
				// TODO: Curl requests will not have this. One idea is to always show
				// html here??
				httpapi.Write(r.Context(), rw, http.StatusBadRequest, codersdk.Response{
					Message: "Internal error deleting OAuth2 client secret.",
					Detail:  err.Error(),
				})
				return
			}

			referer := r.Referer()
			refererU, err := url.Parse(referer)
			if err != nil {
				httpapi.Write(r.Context(), rw, http.StatusBadRequest, codersdk.Response{
					Message: "Internal error deleting OAuth2 client secret.",
					Detail:  err.Error(),
				})
				return
			}

			app := httpmw.OAuth2ProviderApp(r)
			// If the request comes from outside, then we show the html allow page.
			// TODO: Skip this step if the user has already clicked allow before, and
			// we can just reuse the token.
			if originU.Hostname() != accessURL.Hostname() && refererU.Path != "/login/oauth2/authorize" {
				if r.URL.Query().Get("redirected") != "" {
					site.RenderStaticErrorPage(rw, r, site.ErrorPageData{
						Status:       http.StatusInternalServerError,
						HideStatus:   false,
						Title:        "Oauth Redirect Loop",
						Description:  "Oauth redirect loop detected.",
						RetryEnabled: false,
						DashboardURL: accessURL.String(),
						Warnings:     nil,
					})
					return
				}

				redirect := r.URL
				vals := redirect.Query()
				vals.Add("redirected", "true")
				r.URL.RawQuery = vals.Encode()
				site.RenderOAuthAllowPage(rw, r, site.RenderOAuthAllowData{
					AppName:     app.Name,
					Icon:        app.Icon,
					RedirectURI: r.URL.String(),
				})
				return
			}

			next.ServeHTTP(rw, r)
		})
	}
}
