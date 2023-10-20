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
	// ...
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Handle logic for dashboard here, check token validity, etc.
	fmt.Fprintf(w, "Welcome to Dashboard!")
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// ...
}

func findUser(username, password string) (*User, error) {
	collection := mongoClient.Database("paseto").Collection("info") // Nama basis data dan koleksi diubah
	var user User
	filter := bson.M{"username": username, "password": password}
	err := collection.FindOne(context.TODO(), filter).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func generateToken(username string) (string, error) {
	// Ganti "your-secret-key" dengan kunci rahasia yang aman
	secretKey := []byte("123456")

	// Generate PASETO token
	v2 := paseto.NewV2()
	now := time.Now()
	expiration := now.Add(24 * time.Hour) // Token expires in 24 hours

	// Payload adalah data yang ingin Anda sertakan dalam token (contoh: username dan waktu kedaluwarsa)
	payload := map[string]interface{}{
		"username": username,
		"exp":      expiration, // Tambahkan waktu kedaluwarsa ke dalam payload
	}

	// Mengenkripsi payload ke dalam token
	token, err := v2.Encrypt(secretKey, payload, nil)
	if err != nil {
		return "", err
	}
	return token, nil
}
