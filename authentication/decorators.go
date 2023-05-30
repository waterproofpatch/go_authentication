package authentication

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func Authentication(inner func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		log.Printf(
			"Start %s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

		isAuth, _, errString := IsAuthorized(w, r)
		if !isAuth {
			WriteError(w, errString, http.StatusUnauthorized)
			return
		}
		inner(w, r)

		timeTaken := time.Since(start)
		log.Printf(
			"End %s - %s %s - took %d", r.RemoteAddr, r.Method, r.RequestURI, timeTaken)

	}
}

func VerifiedOnly(inner func(http.ResponseWriter, *http.Request, *JWTData), allowUnverified bool) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		log.Printf(
			"Start %s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

		parsed, claims, errorString := IsAuthorized(w, r)
		if !parsed {
			fmt.Printf("User is not authorized, error parsing claims: %s", errorString)
			if !allowUnverified {
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

		timeTaken := time.Since(start)
		log.Printf(
			"End %s - %s %s - took %d", r.RemoteAddr, r.Method, r.RequestURI, timeTaken)

	}
}

func AdminOnly(inner func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		log.Printf(
			"Start %s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

		parsed, claims, _ := IsAuthorized(w, r)
		if !parsed || !claims.IsAdmin {
			if !parsed {
				log.Printf("Failed parsing claims.")
			} else {
				log.Printf("Claims valid, but not admin!")
			}
			log.Printf("Rejecting authentication %s for %s\n", r.Host, r.RequestURI)
			WriteError(w, "Only admin can perform this action.", http.StatusUnauthorized)
			return
		}

		inner(w, r)

		timeTaken := time.Since(start)
		log.Printf(
			"End %s - %s %s - took %d", r.RemoteAddr, r.Method, r.RequestURI, timeTaken)

	}
}
