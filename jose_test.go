package eveauth

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJoseExtractCharacterID(t *testing.T) {
	cases := []struct {
		name        string
		token       jwt.Token
		characterID int
		valid       bool
	}{
		{"happy path", fakeToken{subject: "CHARACTER:EVE:99"}, 99, true},
		{"empty", fakeToken{subject: ""}, 0, false},
		{"incomplete", fakeToken{subject: "CHARACTER:EVE"}, 0, false},
		{"not number", fakeToken{subject: "CHARACTER:EVE:ABC"}, 0, false},
		{"invalid-1", fakeToken{subject: "XXX:EVE:99"}, 0, false},
		{"invalid-2", fakeToken{subject: "CHARACTER:XX:99"}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x, err := extractCharacterID(tc.token)
			if tc.valid {
				if assert.NoError(t, err) {
					assert.Equal(t, tc.characterID, x)
				}
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestExtractCharacterID(t *testing.T) {
	t.Run("can return name", func(t *testing.T) {
		f := newFakeToken()
		f.data["name"] = "Johnny"
		assert.Equal(t, "Johnny", extractCharacterName(f))
	})
	t.Run("should return empty string when not found", func(t *testing.T) {
		f := newFakeToken()
		assert.Equal(t, "", extractCharacterName(f))
	})
}

func TestExtractScopes(t *testing.T) {
	t.Run("can return single scope", func(t *testing.T) {
		f := newFakeToken()
		f.data["scp"] = "alpha"
		got, err := extractScopes(f)
		require.NoError(t, err)
		assert.Equal(t, []string{"alpha"}, got)
	})
	t.Run("can return multiple scopes", func(t *testing.T) {
		f := newFakeToken()
		f.data["scp"] = []any{"alpha"}
		got, err := extractScopes(f)
		require.NoError(t, err)
		assert.Equal(t, []string{"alpha"}, got)
	})
	t.Run("should return empty string when not found", func(t *testing.T) {
		f := newFakeToken()
		got, err := extractScopes(f)
		require.NoError(t, err)
		assert.Len(t, got, 0)
	})
	t.Run("should return error when scope can not be parsed", func(t *testing.T) {
		f := newFakeToken()
		f.data["scp"] = 5
		_, err := extractScopes(f)
		assert.ErrorIs(t, err, ErrInvalid)
	})
}
