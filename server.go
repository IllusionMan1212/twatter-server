package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/illusionman1212/twatter-server/db"
	"github.com/illusionman1212/twatter-server/logger"
	"github.com/illusionman1212/twatter-server/redissession"
	"github.com/illusionman1212/twatter-server/routes"
	"github.com/illusionman1212/twatter-server/sockets"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
)

func main() {
	logger.Initialize()

	err := godotenv.Load()
	if err != nil {
		logger.Fatal(err)
	}

	err = db.InitializeDB()
	if err != nil {
		logger.Fatal(err)
	}

	redissession.InitializeTypes()
	err = redissession.Initialize()
	if err != nil {
		logger.Fatal(err)
	}

	hub := sockets.NewHub()
	go hub.Run()

	cors := cors.New(cors.Options{
		AllowedOrigins:   []string{os.Getenv("ALLOWED_ORIGINS")},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Origin", "Content-Type", "Accept"},
		ExposedHeaders:   []string{"Content-Length", "Content-Type"},
		AllowCredentials: true,
	})

	router := mux.NewRouter().StrictSlash(true)
	apiSubrouter := router.PathPrefix("/api/").Subrouter()
	routes.RegisterUsersRoutes(apiSubrouter)     // only some routes need to validate the user/token
	routes.RegisterMessagingRoutes(apiSubrouter) // all routes need to validate the user/token
	routes.RegisterPostsRoutes(apiSubrouter)     // only some routes need to validate the user/token
	router.HandleFunc("/ws", func(w http.ResponseWriter, req *http.Request) {
		sockets.ServeWs(hub, w, req)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	logger.Infof("Listening on port %v", port)
	http.ListenAndServe(fmt.Sprintf(":%v", port), cors.Handler(router))

	defer db.DBPool.Close()
}
