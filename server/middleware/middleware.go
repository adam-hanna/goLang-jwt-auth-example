package middleware

import (
	"github.com/justinas/alice"
	"log"
	"net/http"
	"time"
	"strings"
	"github.com/adam-hanna/goLang-jwt-auth/server/middleware/myJwt"
	"github.com/adam-hanna/goLang-jwt-auth/server/templates"
	"github.com/adam-hanna/goLang-jwt-auth/db"
)

func NewHandler() http.Handler {
	// this returns a handler that is a chain of all of our other handlers
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler) http.Handler {
	// this catches any errors and returns an internal server error to the client
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Panic("Recovered! Panic: %+v", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}()

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func authHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// do auth stuff
		// include list of restricted paths, comma sep
		// I'm including logout here, bc I don't want a baddie forcing my users to logout
		switch r.URL.Path {
		case "/restricted", "/logout", "/deleteUser":
			log.Println("In auth restricted section")

			// read cookies
			AuthCookie, authErr := r.Cookie("AuthToken")
			if authErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! No auth cookie")
				nullifyTokenCookies(&w, r)
				// http.Redirect(w, r, "/login", 302)
				http.Error(w, http.StatusText(401), 401)
				return
			} else if authErr != nil {
				log.Panic("panic: %+v", authErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			RefreshCookie, refreshErr := r.Cookie("RefreshToken")
			if refreshErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! No refresh cookie")
				nullifyTokenCookies(&w, r)
				http.Redirect(w, r, "/login", 302)
				return
			} else if refreshErr != nil {
				log.Panic("panic: %+v", refreshErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			// grab the csrf token
			requestCsrfToken := grabCsrfFromReq(r)
			log.Println(requestCsrfToken)

			// check the jwt's for validity
			authTokenString, refreshTokenString, csrfSecret, err := myJwt.CheckAndRefreshTokens(AuthCookie.Value, RefreshCookie.Value, requestCsrfToken)
			if err != nil {
				if err.Error() == "Unauthorized" {
					log.Println("Unauthorized attempt! JWT's not valid!")
					// nullifyTokenCookies(&w, r)
					// http.Redirect(w, r, "/login", 302)
					http.Error(w, http.StatusText(401), 401)
					return
				} else {
					// @adam-hanna: do we 401 or 500, here?
					// it could be 401 bc the token they provided was messed up
					// or it could be 500 bc there was some error on our end
					log.Println("err not nil")
					log.Panic("panic: %+v", err)
					// nullifyTokenCookies(&w, r)
					http.Error(w, http.StatusText(500), 500)
					return
				}
			}
			log.Println("Successfully recreated jwts")

			// @adam-hanna: Change this. Only allow whitelisted origins! Also check referer header
			w.Header().Set("Access-Control-Allow-Origin", "*")

			// if we've made it this far, everything is valid!
			// And tokens have been refreshed if need-be
			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfSecret)
			
		default:
			// no jwt check necessary
		}

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	// @adam-hanna: I shouldn't be doing this in my middleware!!!!
	switch r.URL.Path {
	case "/restricted":
		csrfSecret := grabCsrfFromReq(r)
		templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{ csrfSecret, "Stoofs!" })

	case "/login":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "login", &templates.LoginPage{ false, "" })

		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			user, uuid, loginErr := db.LogUserIn(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""))
			log.Println(user, uuid, loginErr)
			if loginErr != nil {
				// login err
				// templates.RenderTemplate(w, "login", &templates.LoginPage{ true, "Login failed\n\nIncorrect username or password" })
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				// no login err
				// now generate cookies for this user
				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, user.Role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}

				// set the cookies to these newly created jwt's
				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)

				w.WriteHeader(http.StatusOK)
			}

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/register":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "register", &templates.RegisterPage{ false, "" })
		
		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			// check to see if the username is already taken
			_, uuid, err := db.FetchUserByUsername(strings.Join(r.Form["username"], ""))
			if err == nil {
				// templates.RenderTemplate(w, "register", &templates.RegisterPage{ true, "Username not available!" })
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				// nope, now create this user
				role := "user"
				uuid, err = db.StoreUser(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""), role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}
				log.Println("uuid: " + uuid)

				// now generate cookies for this user
				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}

				// set the cookies to these newly created jwt's
				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)

				w.WriteHeader(http.StatusOK)
			}

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/logout":
		// remove this user's ability to make requests
		nullifyTokenCookies(&w, r)
		// use 302 to force browser to do GET request
		http.Redirect(w, r, "/login", 302)

	case "/deleteUser":
		log.Println("Deleting user")

		// grab auth cookie
		AuthCookie, authErr := r.Cookie("AuthToken")
		if authErr == http.ErrNoCookie {
			log.Println("Unauthorized attempt! No auth cookie")
			nullifyTokenCookies(&w, r)
			http.Redirect(w, r, "/login", 302)
			return
		} else if authErr != nil {
			log.Panic("panic: %+v", authErr)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		uuid, uuidErr := myJwt.GrabUUID(AuthCookie.Value)
		if uuidErr != nil {
			log.Panic("panic: %+v", uuidErr)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		db.DeleteUser(uuid)
		// remove this user's ability to make requests
		nullifyTokenCookies(&w, r)
		// use 302 to force browser to do GET request
		http.Redirect(w, r, "/register", 302)

	default:
		w.WriteHeader(http.StatusOK)
	}
}

func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{
		Name: "AuthToken",
		Value: "",
		Expires: time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name: "RefreshToken",
		Value: "",
		Expires: time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(*w, &refreshCookie)

	// if present, revoke the refresh cookie from our db
	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie {
		// do nothing, there is no refresh cookie present
		return
	} else if refreshErr != nil {
		log.Panic("panic: %+v", refreshErr)
		http.Error(*w, http.StatusText(500), 500)
	}

	myJwt.RevokeRefreshToken(RefreshCookie.Value)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString string, refreshTokenString string) {
	authCookie := http.Cookie{
		Name: "AuthToken",
		Value: authTokenString,
		HttpOnly: true,
	}

	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name: "RefreshToken",
		Value: refreshTokenString,
		HttpOnly: true,
	}

	http.SetCookie(*w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string {
	csrfFromFrom := r.FormValue("X-CSRF-Token")

	if csrfFromFrom != "" {
		return csrfFromFrom
	} else {
		return r.Header.Get("X-CSRF-Token")
	}
}