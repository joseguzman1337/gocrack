package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/fireeye/gocrack/server/storage"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	uuid "github.com/satori/go.uuid"
)

const (
	csrfCookieName  = "XSRF-TOKEN"
	csrfHeaderName  = "X-Xsrf-Token"
	csrfTokenSep    = "."
)

var (
	currentCSRFSecret string
	currentCSRFSecure bool
)

// logAction records potentially sensitive actions to the database for auditing purposes
func (s *Server) logAction(action storage.ActivityType, entityID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claim := getClaimInformation(c)
		record := storage.ActivityLogEntry{
			OccuredAt: time.Now().UTC(),
			UserUUID:  claim.UserUUID,
			Type:      action,
			EntityID:  c.Param(entityID),
			Path:      c.Request.URL.EscapedPath(),
			IPAddress: c.ClientIP(),
		}

		c.Next()

		record.StatusCode = c.Writer.Status()
		if err := s.stor.LogActivity(record); err != nil {
			log.Error().Interface("record", record).Err(err).Msg("Failed to write activity log to database")
		}
	}
}

// checkIfUserIsAdmin ensures the user is an administrator before allowing the rest of the chain to continue
func checkIfUserIsAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		claim := getClaimInformation(c)
		if !claim.IsAdmin {
			c.JSON(http.StatusUnauthorized, &WebAPIError{
				StatusCode: http.StatusUnauthorized,
				UserError:  "You do not have permissions to access this route",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// setSecureHeaders sets some standard secure headers to the responses
func setSecureHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Option", "nosniff")

		c.Next()
	}
}

// setXSRFTokenIfNecessary will grab the CSRF token for a request and set it as a response cookie if needed
func setXSRFTokenIfNecessary(enabled bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !enabled {
			c.Next()
			return
		}

		claim := getClaimInformation(c)
		if claim == nil {
			goto SetCookie
		}

		// If the claim is strictly API use, enable a CSRF bypass
		if claim.APIOnly {
			c.Next()
			return
		}

	SetCookie:
		setCSRFCookie(c, currentCSRFSecret, currentCSRFSecure)
		c.Next()
	}
}

func protectCSRF(enabled bool, secret string, secure bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !enabled {
			c.Next()
			return
		}

		claim := getClaimInformation(c)
		if claim != nil && claim.APIOnly {
			c.Next()
			return
		}

		setCSRFCookie(c, secret, secure)
		if isSafeMethod(c.Request.Method) {
			c.Next()
			return
		}

		token := c.GetHeader(csrfHeaderName)
		if !validateCSRFCookie(secret, token) {
			log.Error().
				Str("client", c.Request.RemoteAddr).
				Msg("A client failed CSRF protection")
			c.AbortWithStatusJSON(http.StatusForbidden, &apiError{Error: "CSRF Validation Failed"})
			return
		}

		c.Next()
	}
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func setCSRFCookie(c *gin.Context, secret string, secure bool) {
	if token, ok := validCSRFCookie(c.Request); ok {
		c.Header(csrfHeaderName, token)
		return
	}

	token, err := newCSRFCookieToken(secret)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate CSRF token")
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		HttpOnly: false,
		Path:     "/",
		Secure:   secure,
	})
	c.Header(csrfHeaderName, token)
}

func validCSRFCookie(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

func validateCSRFCookie(secret, token string) bool {
	parts := strings.Split(token, csrfTokenSep)
	if len(parts) != 2 {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0]))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(parts[1]), []byte(expected))
}

func newCSRFCookieToken(secret string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return payload + csrfTokenSep + hex.EncodeToString(mac.Sum(nil)), nil
}

// checkIfUserIsEntitled ensures the user is able to access the document.
func (s *Server) checkIfUserIsEntitled(entityIDLookup string, documentType storage.EntitlementType) gin.HandlerFunc {
	return func(c *gin.Context) {
		claim := getClaimInformation(c)

		// If they're not an admin, let's look them up to ensure they're entitled to the document
		if !claim.IsAdmin {
			canAccess, err := s.stor.CheckEntitlement(claim.UserUUID, c.Param(entityIDLookup), documentType)
			if err != nil {
				if err == storage.ErrNotFound {
					goto CantAccess
				}
				c.JSON(http.StatusInternalServerError, &WebAPIError{
					StatusCode: http.StatusInternalServerError,
					Err:        err,
				})
				c.Abort()
				return
			}

			if canAccess {
				c.Next()
				return
			}

			goto CantAccess
		CantAccess:
			c.JSON(http.StatusNotFound, &WebAPIError{
				StatusCode: http.StatusNotFound,
				Err:        err,
				UserError:  "The requested file does not exist or you do not have permissions to it",
			})
			c.Abort()
			return
		}

		// Continue if all is well
		c.Next()
	}
}

// checkParamValidUUID ensures the UUID in the HTTP route is valid
func checkParamValidUUID(paramName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if uid := c.Param(paramName); uid != "" {
			if _, err := uuid.FromString(uid); err != nil {
				goto Error
			}
			// UUID checks out
			c.Next()
			return
		}

		// Will fallthrough here if uid is ""
	Error:
		c.JSON(http.StatusBadRequest, &WebAPIError{
			StatusCode:            http.StatusBadRequest,
			CanErrorBeShownToUser: false,
			UserError:             "The UUID in the HTTP Path is not valid",
		})
		c.Abort()

	}
}
