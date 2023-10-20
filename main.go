package main

import (
	"context"
	"html/template"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/o1egl/paseto/v4"
	"github.com/o1egl/paseto/v4/parsing"
	"github.com/o1egl/paseto/v4/payload"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var mongoClient *mongo.Client

type User struct {
	Username string `bson:"username"`
	Password string `bson:"password"`
}

func main() {
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		panic(err)
	}
	mongoClient = client

	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/dashboard", dashboardHandler).Methods("GET")
	r.HandleFunc("/logout", logoutHandler).Methods("POST")

	http.Handle("/", r)
	http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		user, err := findUser(r.FormValue("username"), r.FormValue("password"))
		if err != nil {
			http.Error(w, "Invalid login credentials", http.StatusUnauthorized)
			return
		}

		// Generate PASETO token
		token, err := generateToken(user.Username)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// Set cookie with PASETO token
		expires := time.Now().Add(24 * time.Hour)
		cookie := http.Cookie{
			Name:     "token",
			Value:    token,
			Expires:  expires,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
		}
		http.SetCookie(w, &cookie)

		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// Check if user already logged in
	cookie, err := r.Cookie("token")
	if err == nil && cookie.Value != "" {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	http.ServeFile(w, r, "login.html")
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	username, err := getUsernameFromToken(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	tmpl, err := template.ParseFiles("dashboard.html")
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Username string
	}{
		Username: username,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Delete the cookie by setting an expired time
	cookie := http.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}
	http.SetCookie(w, &cookie)

	// Redirect to login page
	http.Redirect(w, r, "/login", http.StatusFound)
}

func findUser(username, password string) (*User, error) {
	// Implementasi pencarian user di database MongoDB
	return nil, nil
}

func generateToken(username string) (string, error) {
	secretKey := []byte("123456") // Ganti dengan secret key yang aman

	// PASETO v4
	v4 := paseto.NewV4()

	// Membuat payload PASETO
	pl := payload.New(map[string]interface{}{
		"username": username,
	})

	// Membuat PASETO token
	token, err := v4.Sign(secretKey, pl, parsing.NewV4())
	if err != nil {
		return "", err
	}

	return token, nil
}

func getUsernameFromToken(token string) (string, error) {
	secretKey := []byte("123456") // Ganti dengan secret key yang sama dengan yang digunakan saat generate token

	// PASETO v4
	v4 := paseto.NewV4()

	// Verifikasi PASETO token
	var pl map[string]interface{}
	err := v4.Verify(token, secretKey, &pl, parsing.NewV4())
	if err != nil {
		return "", err
	}

	// Mendapatkan username dari payload
	username, ok := pl["username"].(string)
	if !ok {
		return "", err
	}

	return username, nil
}
