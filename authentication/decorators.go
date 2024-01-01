package authentication

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/waterproofpatch/go_authentication/types"
)

func Authentication(inner func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s:%s\n", r.Method, r.RequestURI)

		isAuth, _, errString, _ := IsAuthorized(w, r)
		if !isAuth {
			WriteError(w, errString, http.StatusUnauthorized)
			return
		}
		inner(w, r)
	}
}

func VerifiedOnly(inner func(http.ResponseWriter, *http.Request, *types.JWTData), allowUnverified bool) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s:%s\n", r.Method, r.RequestURI)

		parsed, claims, errorString, reason := IsAuthorized(w, r)
		if !parsed {
			fmt.Printf("User is not authorized, error parsing claims: %s, reason=%s\n", errorString, reason)
			// even if we're allowing unverified users, if the user
			// sent a token but it's expired, we want to send them
			// the unauthorized error so their frontend can do
			// something sensible with it
			if !allowUnverified || reason == EXPIRED {
				WriteError(w, "Must be logged in to perform this action.", http.StatusUnauthorized)
				return
			}
		} else if !claims.IsVerified {
			if !allowUnverified {
				WriteError(w, "Only verified accounts can perform this action", http.StatusUnauthorized)
				return
			}
		}

		inner(w, r, claims)
	}
}

func AdminOnly(inner func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		log.Printf(
			"Start %s - %s %s\n", r.RemoteAddr, r.Method, r.RequestURI)

		parsed, claims, _, _ := IsAuthorized(w, r)
		if !parsed || !claims.IsAdmin {
			if !parsed {
				log.Printf("Failed parsing claims.\n")
			} else {
				log.Printf("Claims valid, but not admin!\n")
			}
			log.Printf("Rejecting authentication %s for %s\n", r.Host, r.RequestURI)
			WriteError(w, "Only admin can perform this action.", http.StatusUnauthorized)
			return
		}

		inner(w, r)

		timeTaken := time.Since(start)
		log.Printf(
			"End %s - %s %s - took %d\n", r.RemoteAddr, r.Method, r.RequestURI, timeTaken)
	}
}
