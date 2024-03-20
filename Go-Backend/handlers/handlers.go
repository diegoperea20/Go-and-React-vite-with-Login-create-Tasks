package handlers

import (
	"encoding/json"
	"fmt"
	"gorm/db"
	"gorm/models"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func GetUsers(rw http.ResponseWriter, r *http.Request) {
	users := models.Users{}
	db.Database.Find(&users)
	sendData(rw, users, http.StatusOK)
}

func GetUser(rw http.ResponseWriter, r *http.Request) {
	if user, err := getUserById(r); err != nil {
		sendError(rw, http.StatusNotFound)
	} else {
		sendData(rw, user, http.StatusOK)
	}

}

func getUserById(r *http.Request) (models.User, *gorm.DB) {
	//Obtener ID
	vars := mux.Vars(r)
	userId, _ := strconv.Atoi(vars["id"])
	user := models.User{}

	if err := db.Database.First(&user, userId); err.Error != nil {
		return user, err
	} else {
		return user, nil
	}
}

func CreateUser(rw http.ResponseWriter, r *http.Request) {
    user := models.User{}
    decoder := json.NewDecoder(r.Body)

    if err := decoder.Decode(&user); err != nil {
        sendError(rw, http.StatusUnprocessableEntity)
        return
    }

    // Generar hash de la contraseña
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        sendError(rw, http.StatusInternalServerError)
        return
    }

    // Asignar el hash de la contraseña al usuario
    user.Password = string(hashedPassword)

    // Guardar el usuario en la base de datos
    db.Database.Save(&user)

    sendData(rw, user, http.StatusCreated)
}

func UpdateUser(rw http.ResponseWriter, r *http.Request) {
    // Obtener ID del usuario a actualizar
    vars := mux.Vars(r)
    userID, _ := strconv.Atoi(vars["id"])

    // Obtener el usuario de la base de datos
    userToUpdate := models.User{}
    if err := db.Database.First(&userToUpdate, userID).Error; err != nil {
        sendError(rw, http.StatusNotFound)
        return
    }

    // Decodificar los datos actualizados del usuario del cuerpo de la solicitud
    updatedUser := models.User{}
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&updatedUser); err != nil {
        sendError(rw, http.StatusUnprocessableEntity)
        return
    }

    // Generar hash de la contraseña si se proporciona una nueva contraseña
    if updatedUser.Password != "" {
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updatedUser.Password), bcrypt.DefaultCost)
        if err != nil {
            sendError(rw, http.StatusInternalServerError)
            return
        }
        updatedUser.Password = string(hashedPassword)
    } else {
        // Si no se proporciona una nueva contraseña, mantener la contraseña existente
        updatedUser.Password = userToUpdate.Password
    }

    // Actualizar el usuario en la base de datos
    updatedUser.Id = int64(userID) // Asignar ID al usuario actualizado
    if err := db.Database.Save(&updatedUser).Error; err != nil {
        sendError(rw, http.StatusInternalServerError)
        return
    }

    sendData(rw, updatedUser, http.StatusOK)
}

func DeleteUser(rw http.ResponseWriter, r *http.Request) {

	if user, err := getUserById(r); err != nil {
		sendError(rw, http.StatusNotFound)
	} else {
		db.Database.Delete(&user)
		sendData(rw, user, http.StatusOK)
	}
}


//login
// Función para el inicio de sesión
func Login(rw http.ResponseWriter, r *http.Request) {
    // Decodificar los datos del cuerpo de la solicitud
    var credentials struct {
        User     string `json:"user"`
        Password string `json:"password"`
    }
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&credentials); err != nil {
        sendError(rw, http.StatusBadRequest)
        return
    }

    // Buscar al usuario en la base de datos
    user := models.User{}
    if err := db.Database.Where("user = ?", credentials.User).First(&user).Error; err != nil {
        sendErrorWithStatus(rw, "Credenciales inválidas", http.StatusUnauthorized)
        return
    }

    // Verificar la contraseña
    if !checkPassword(credentials.Password, user.Password) {
        sendErrorWithStatus(rw, "Credenciales inválidas", http.StatusUnauthorized)
        return
    }

    // Generar el token JWT
    tokenString, err := generateToken(user)
    if err != nil {
        sendError(rw, http.StatusInternalServerError)
        return
    }

    // Respuesta exitosa con el token y el ID de usuario
    response := map[string]interface{}{
        "token":   tokenString,
        "user_id": user.Id,
    }
    sendData(rw, response, http.StatusOK)
}


// Función para enviar un error con un código de estado HTTP específico
func sendErrorWithStatus(rw http.ResponseWriter, errorMessage string, statusCode int) {
    rw.Header().Set("Content-Type", "application/json")
    rw.WriteHeader(statusCode)

    response := map[string]string{"error": errorMessage}
    jsonResponse, _ := json.Marshal(response)
    fmt.Fprintln(rw, string(jsonResponse))
}
// Función para verificar la contraseña
func checkPassword(inputPassword string, storedPassword string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
    return err == nil
}

// Función para generar el token JWT
func generateToken(user models.User) (string, error) {
    // Definir la clave secreta para firmar el token (cambia esto a tu clave secreta real)
    secretKey := []byte("tuclavesecretadeltoken")

    // Crear el token con los datos del usuario y una fecha de expiración
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user_id": user.Id,
        "exp":     time.Now().Add(time.Hour).Unix(), // Token expira en 1 hora
    })

    // Firmar el token y obtener su representación en string
    tokenString, err := token.SignedString(secretKey)
    if err != nil {
        return "", err
    }
    return tokenString, nil
}


//Tasks
// Crear tarea
func CreateTask(rw http.ResponseWriter, r *http.Request) {
    task := models.Task{}
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&task); err != nil {
        sendError(rw, http.StatusUnprocessableEntity)
        return
    }

    db.Database.Create(&task)
    sendData(rw, task, http.StatusCreated)
}

// Obtener todas las tareas
func GetTasks(rw http.ResponseWriter, r *http.Request) {
    tasks := models.Tasks{}
    db.Database.Find(&tasks)
    sendData(rw, tasks, http.StatusOK)
}

// Obtener tareas por usuario
func GetTasksByUser(rw http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    user := vars["user"]

    tasks := models.Tasks{}
    db.Database.Where("user = ?", user).Find(&tasks)
    sendData(rw, tasks, http.StatusOK)
}

// Actualizar tarea
func UpdateTask(rw http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id, _ := strconv.Atoi(vars["id"])

    task := models.Task{}
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&task); err != nil {
        sendError(rw, http.StatusUnprocessableEntity)
        return
    }

    task.Id = int64(id)
    db.Database.Save(&task)
    sendData(rw, task, http.StatusOK)
}


// Eliminar tarea por ID
func DeleteTask(rw http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id, _ := strconv.Atoi(vars["id"])

    task := models.Task{}
    if err := db.Database.First(&task, id).Error; err != nil {
        sendError(rw, http.StatusNotFound)
        return
    }

    db.Database.Delete(&task)
    sendData(rw, task, http.StatusOK)
}

// Eliminar todas las tareas de un usuario
func DeleteAllTasksByUser(rw http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    user := vars["user"]

    tasks := models.Tasks{}
    db.Database.Where("user = ?", user).Find(&tasks)

    for _, task := range tasks {
        db.Database.Delete(&task)
    }

    sendData(rw, tasks, http.StatusOK)
}

// Obtener tarea por ID y usuario
func GetTaskWithId(rw http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id, _ := strconv.Atoi(vars["id"])
    user := vars["user"]

    task := models.Task{}
    if err := db.Database.Where("id = ? AND user = ?", id, user).First(&task).Error; err != nil {
        sendError(rw, http.StatusNotFound)
        return
    }

    // Enviar la tarea como un arreglo
    sendData(rw, []models.Task{task}, http.StatusOK)
}


//filters
func GetSameTitleCount(rw http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    user := vars["user"]

    // Consultar títulos y contar ocurrencias
    var result []map[string]interface{}
    db.Database.Raw("SELECT title, COUNT(*) as count FROM tasks WHERE title IN (SELECT title FROM tasks WHERE user = ?) AND user != ? GROUP BY title", user, user).Scan(&result)

    // Preparar respuesta
    var response []map[string]interface{}
    for _, item := range result {
        count, _ := item["count"].(int64)
        title, _ := item["title"].(string)
        response = append(response, map[string]interface{}{
            "Number of titles": count,
            "title":            title,
        })
    }

    sendData(rw, response, http.StatusOK)
}






// Obtener títulos iguales y correos electrónicos para un usuario// Obtener títulos iguales y correos electrónicos para un usuario
// Obtener títulos iguales y correos electrónicos para un usuario
func GetSameTitleEmail(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    user := vars["user"]

    // Consultar títulos y correos electrónicos
    var result []map[string]interface{}
    db.Database.Raw("SELECT title, GROUP_CONCAT(email) AS emails FROM tasks INNER JOIN users ON tasks.user = users.user WHERE title IN (SELECT title FROM tasks WHERE user = ?) AND tasks.user != ? GROUP BY title", user, user).Scan(&result)

    // Preparar respuesta
    var response []map[string]interface{}
    for _, item := range result {
        title, _ := item["title"].(string)
        emailsStr, _ := item["emails"].(string)
        emails := strings.Split(emailsStr, ",")
        response = append(response, map[string]interface{}{
            "title":  title,
            "emails": emails,
        })
    }

    sendData(w, response, http.StatusOK)
}
