package dbcrypt

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coder/coder/v2/coderd/database"
	"github.com/coder/coder/v2/coderd/database/dbgen"
	"github.com/coder/coder/v2/coderd/database/dbtestutil"
)

func TestUserLinks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("InsertUserLink", func(t *testing.T) {
		t.Parallel()
		db, crypt, cipher := setup(t)
		user := dbgen.User(t, crypt, database.User{})
		link := dbgen.UserLink(t, crypt, database.UserLink{
			UserID:            user.ID,
			OAuthAccessToken:  "access",
			OAuthRefreshToken: "refresh",
		})
		require.Equal(t, link.OAuthAccessToken, "access")
		require.Equal(t, link.OAuthRefreshToken, "refresh")

		link, err := db.GetUserLinkByLinkedID(ctx, link.LinkedID)
		require.NoError(t, err)
		requireEncryptedEquals(t, cipher, link.OAuthAccessToken, "access")
		requireEncryptedEquals(t, cipher, link.OAuthRefreshToken, "refresh")
	})

	t.Run("UpdateUserLink", func(t *testing.T) {
		t.Parallel()
		db, crypt, cipher := setup(t)
		user := dbgen.User(t, crypt, database.User{})
		link := dbgen.UserLink(t, crypt, database.UserLink{
			UserID: user.ID,
		})
		updated, err := crypt.UpdateUserLink(ctx, database.UpdateUserLinkParams{
			OAuthAccessToken:  "access",
			OAuthRefreshToken: "refresh",
			UserID:            link.UserID,
			LoginType:         link.LoginType,
		})
		require.NoError(t, err)
		require.Equal(t, updated.OAuthAccessToken, "access")
		require.Equal(t, updated.OAuthRefreshToken, "refresh")

		link, err = db.GetUserLinkByLinkedID(ctx, link.LinkedID)
		require.NoError(t, err)
		requireEncryptedEquals(t, cipher, link.OAuthAccessToken, "access")
		requireEncryptedEquals(t, cipher, link.OAuthRefreshToken, "refresh")
	})

	t.Run("GetUserLinkByLinkedID", func(t *testing.T) {
		t.Parallel()
		db, crypt, cipher := setup(t)
		user := dbgen.User(t, crypt, database.User{})
		link := dbgen.UserLink(t, crypt, database.UserLink{
			UserID:            user.ID,
			OAuthAccessToken:  "access",
			OAuthRefreshToken: "refresh",
		})
		link, err := db.GetUserLinkByLinkedID(ctx, link.LinkedID)
		require.NoError(t, err)
		requireEncryptedEquals(t, cipher, link.OAuthAccessToken, "access")
		requireEncryptedEquals(t, cipher, link.OAuthRefreshToken, "refresh")
	})

	t.Run("GetUserLinkByUserIDLoginType", func(t *testing.T) {
		t.Parallel()
		db, crypt, cipher := setup(t)
		user := dbgen.User(t, crypt, database.User{})
		link := dbgen.UserLink(t, crypt, database.UserLink{
			UserID:            user.ID,
			OAuthAccessToken:  "access",
			OAuthRefreshToken: "refresh",
		})
		link, err := db.GetUserLinkByUserIDLoginType(ctx, database.GetUserLinkByUserIDLoginTypeParams{
			UserID:    link.UserID,
			LoginType: link.LoginType,
		})
		require.NoError(t, err)
		requireEncryptedEquals(t, cipher, link.OAuthAccessToken, "access")
		requireEncryptedEquals(t, cipher, link.OAuthRefreshToken, "refresh")
	})
}

func TestGitAuthLinks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("InsertGitAuthLink", func(t *testing.T) {
		t.Parallel()
		db, crypt, cipher := setup(t)
		link := dbgen.GitAuthLink(t, crypt, database.GitAuthLink{
			OAuthAccessToken:  "access",
			OAuthRefreshToken: "refresh",
		})
		require.Equal(t, link.OAuthAccessToken, "access")
		require.Equal(t, link.OAuthRefreshToken, "refresh")

		link, err := db.GetGitAuthLink(ctx, database.GetGitAuthLinkParams{
			ProviderID: link.ProviderID,
			UserID:     link.UserID,
		})
		require.NoError(t, err)
		requireEncryptedEquals(t, cipher, link.OAuthAccessToken, "access")
		requireEncryptedEquals(t, cipher, link.OAuthRefreshToken, "refresh")
	})

	t.Run("UpdateGitAuthLink", func(t *testing.T) {
		t.Parallel()
		db, crypt, cipher := setup(t)
		link := dbgen.GitAuthLink(t, crypt, database.GitAuthLink{})
		updated, err := crypt.UpdateGitAuthLink(ctx, database.UpdateGitAuthLinkParams{
			ProviderID:        link.ProviderID,
			UserID:            link.UserID,
			OAuthAccessToken:  "access",
			OAuthRefreshToken: "refresh",
		})
		require.NoError(t, err)
		require.Equal(t, updated.OAuthAccessToken, "access")
		require.Equal(t, updated.OAuthRefreshToken, "refresh")

		link, err = db.GetGitAuthLink(ctx, database.GetGitAuthLinkParams{
			ProviderID: link.ProviderID,
			UserID:     link.UserID,
		})
		require.NoError(t, err)
		requireEncryptedEquals(t, cipher, link.OAuthAccessToken, "access")
		requireEncryptedEquals(t, cipher, link.OAuthRefreshToken, "refresh")
	})

	t.Run("GetGitAuthLink", func(t *testing.T) {
		t.Parallel()
		db, crypt, cipher := setup(t)
		link := dbgen.GitAuthLink(t, crypt, database.GitAuthLink{
			OAuthAccessToken:  "access",
			OAuthRefreshToken: "refresh",
		})
		link, err := db.GetGitAuthLink(ctx, database.GetGitAuthLinkParams{
			UserID:     link.UserID,
			ProviderID: link.ProviderID,
		})
		require.NoError(t, err)
		requireEncryptedEquals(t, cipher, link.OAuthAccessToken, "access")
		requireEncryptedEquals(t, cipher, link.OAuthRefreshToken, "refresh")
	})
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("OK", func(t *testing.T) {
		t.Parallel()
		// Given: a cipher is loaded
		cipher := ciphers(initCipher(t))
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		rawDB, _ := dbtestutil.NewDB(t)

		// When: we init the crypt db
		cryptDB, err := New(ctx, rawDB, cipher)
		require.NoError(t, err)

		// Then: the sentinel value is encrypted
		cryptVal, err := cryptDB.GetDBCryptSentinelValue(ctx)
		require.NoError(t, err)
		require.Equal(t, "coder", cryptVal)

		rawVal, err := rawDB.GetDBCryptSentinelValue(ctx)
		require.NoError(t, err)
		require.Contains(t, rawVal, MagicPrefix)
		requireEncryptedEquals(t, cipher, rawVal, "coder")
	})

	t.Run("NoCipher", func(t *testing.T) {
		t.Parallel()
		// Given: no cipher is loaded
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		rawDB, _ := dbtestutil.NewDB(t)

		// When: we init the crypt db
		_, err := New(ctx, rawDB, nil)

		// Then: an error is returned
		require.ErrorContains(t, err, "no ciphers configured")

		// And: the sentinel value is not present
		_, err = rawDB.GetDBCryptSentinelValue(ctx)
		require.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("CipherChanged", func(t *testing.T) {
		t.Parallel()
		// Given: no cipher is loaded
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		rawDB, _ := dbtestutil.NewDB(t)

		// And: the sentinel value is encrypted with a different cipher
		cipher1 := initCipher(t)
		field := sentinelValue
		encrypted, err := ciphers(cipher1).Encrypt([]byte(field))
		require.NoError(t, err)
		b64encrypted := base64.StdEncoding.EncodeToString(encrypted)
		require.NoError(t, rawDB.SetDBCryptSentinelValue(ctx, MagicPrefix+b64encrypted))

		// When: we init the crypt db with no access to the old cipher
		cipher2 := initCipher(t)
		_, err = New(ctx, rawDB, ciphers(cipher2))
		// Then: a special error is returned
		var derr *DecryptFailedError
		require.ErrorAs(t, err, &derr)

		// And the sentinel value should remain unchanged. For now.
		rawVal, err := rawDB.GetDBCryptSentinelValue(ctx)
		require.NoError(t, err)
		requireEncryptedEquals(t, ciphers(cipher1), rawVal, field)

		// When: we set the secondary cipher
		cs := ciphers(cipher2, cipher1)
		_, err = New(ctx, rawDB, cs)
		// Then: no error is returned
		require.NoError(t, err)

		// And the sentinel value should be re-encrypted with the new value.
		rawVal, err = rawDB.GetDBCryptSentinelValue(ctx)
		require.NoError(t, err)
		requireEncryptedEquals(t, ciphers(cipher2), rawVal, field)
	})
}

func requireEncryptedEquals(t *testing.T, c Cipher, value, expected string) {
	t.Helper()
	require.Greater(t, len(value), 8, "value is not encrypted")
	require.Equal(t, MagicPrefix, value[:8], "missing magic prefix")
	data, err := base64.StdEncoding.DecodeString(value[8:])
	require.NoError(t, err, "invalid base64")
	require.Greater(t, len(data), 8, "missing cipher digest")
	require.Equal(t, c.HexDigest(), string(data[:7]), "cipher digest mismatch")
	got, err := c.Decrypt(data)
	require.NoError(t, err, "failed to decrypt data")
	require.Equal(t, expected, string(got), "decrypted data does not match")
}

func initCipher(t *testing.T) *aes256 {
	t.Helper()
	key := make([]byte, 32) // AES-256 key size is 32 bytes
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)
	c, err := cipherAES256(key)
	require.NoError(t, err)
	return c
}

func setup(t *testing.T) (db, cryptodb database.Store, cs *Ciphers) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rawDB, _ := dbtestutil.NewDB(t)

	_, err := rawDB.GetDBCryptSentinelValue(ctx)
	require.ErrorIs(t, err, sql.ErrNoRows)

	cs = ciphers(initCipher(t))
	cryptDB, err := New(ctx, rawDB, cs)
	require.NoError(t, err)

	rawVal, err := rawDB.GetDBCryptSentinelValue(ctx)
	require.NoError(t, err)
	require.Contains(t, rawVal, MagicPrefix)

	cryptVal, err := cryptDB.GetDBCryptSentinelValue(ctx)
	require.NoError(t, err)
	require.Equal(t, "coder", cryptVal)

	return rawDB, cryptDB, cs
}
