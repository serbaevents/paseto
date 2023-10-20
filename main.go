package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/o1egl/paseto"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var mongoClient *mongo.Client

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
	r.HandleFunc("/logout", logoutHandler).Methods("GET")

	http.Handle("/", r)
	http.ListenAndServe(":8080", nil)
}

type User struct {
	Username string `bson:"username"`
	Password string `bson:"password"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Validasi login (misalnya, dari MongoDB)
		user, err := findUser(username, password)
		if err != nil {
			http.Error(w, "Invalid login credentials", http.StatusUnauthorized)
			return
		}

		// Generate PASETO token
		token := generateToken(user.Username)

		// Set cookie with token
		expires := time.Now().Add(24 * time.Hour)
		cookie := http.Cookie{
			Name:     "token",
			Value:    token,
			Expires:  expires,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		}
		http.SetCookie(w, &cookie)

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

	// TODO: Handle dashboard logic here, check token validity, etc.
	fmt.Fprintf(w, "Welcome to Dashboard!")
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Delete token cookie
	cookie := http.Cookie{
		Name:   "token",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, "/login", http.StatusFound)
}

func findUser(username, password string) (*User, error) {
	collection := mongoClient.Database("mydb").Collection("users")
	var user User
	filter := bson.M{"username": username, "password": password}
	err := collection.FindOne(context.TODO(), filter).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func generateToken(username string) string {
	// Generate PASETO token
	v2 := paseto.NewV2()
	now := time.Now()
	expiration := now.Add(24 * time.Hour) // Token expires in 24 hours

	token, err := v2.Encrypt([]byte("your-secret-key"), nil, username, now, expiration, nil)
	if err != nil {
		panic(err)
	}
	return token
}
