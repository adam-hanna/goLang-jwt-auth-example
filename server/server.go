package server

import (
	"log"
	"net/http"
	"github.com/adam-hanna/goLang-jwt-auth-example/server/middleware"
)

func StartServer(hostname string, port string) error {
	host := hostname + ":" + port

	log.Printf("Listening on: %s", host)

	handler := middleware.NewHandler()

	http.Handle("/", handler)
	return http.ListenAndServe(host, nil)
}