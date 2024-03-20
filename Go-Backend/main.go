package main

import (
	"gorm/handlers"
	"gorm/models"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

func main() {

	models.MigrarUser()
    models.MigrarTask()

	//Rutas
	mux := mux.NewRouter()

	// Middleware CORS con opciones personalizadas
    corsOptions := cors.New(cors.Options{
        AllowedOrigins: []string{"http://localhost:5173"}, // Reemplaza con la URL de tu frontend React
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
    })
    handler := corsOptions.Handler(mux)

    // Endpoints
    mux.HandleFunc("/loginup", handlers.GetUsers).Methods("GET")
    mux.HandleFunc("/loginup/{id:[0-9]+}", handlers.GetUser).Methods("GET")
    mux.HandleFunc("/loginup", handlers.CreateUser).Methods("POST")
    mux.HandleFunc("/loginup/{id:[0-9]+}", handlers.UpdateUser).Methods("PUT")
    mux.HandleFunc("/loginup/{id:[0-9]+}", handlers.DeleteUser).Methods("DELETE")
    //login
    mux.HandleFunc("/", handlers.Login).Methods("POST")
    //tasks
    mux.HandleFunc("/tasks", handlers.CreateTask).Methods("POST")
    mux.HandleFunc("/tasks", handlers.GetTasks).Methods("GET")
    mux.HandleFunc("/tasks/{user}", handlers.GetTasksByUser).Methods("GET")
    mux.HandleFunc("/tasks/{id}", handlers.UpdateTask).Methods("PUT")
    mux.HandleFunc("/tasks/{id}", handlers.DeleteTask).Methods("DELETE")
    mux.HandleFunc("/tasks/deleteall/{user}", handlers.DeleteAllTasksByUser).Methods("DELETE")
    mux.HandleFunc("/tasks/{id}/{user}", handlers.GetTaskWithId).Methods("GET")
    //filters
    mux.HandleFunc("/countsames/{user}", handlers.GetSameTitleCount).Methods("GET")
    mux.HandleFunc("/countsame/{user}", handlers.GetSameTitleEmail).Methods("GET") 
    log.Fatal(http.ListenAndServe(":5000", handler))

}


/* Comands for use docker container mysql
docker run --name mymysql -e MYSQL_ROOT_PASSWORD=mypassword -p 3306:3306 -d mysql:latest
docker exec -it mymysql bash
mysql -u root -p
create database gomysql; */

/* Cuando defines rutas en un enrutador como Gorilla Mux, estás especificando patrones de ruta para coincidir con las solicitudes entrantes. En tu caso, al definir la ruta como /tasks/countsames/{user}, estás especificando un patrón de ruta que espera que todas las solicitudes comiencen con /tasks/countsames/ seguido de un parámetro {user}.

La diferencia clave entre /tasks/countsames/{user} y /countsames/{user} es que la primera ruta espera que la URL comience exactamente con /tasks/countsames/, mientras que la segunda ruta simplemente espera que comience con /countsames/. */