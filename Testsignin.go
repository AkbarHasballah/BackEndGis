package BEGis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type Userss struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var Privatekey = "56e4eb16f428e82cea21e5bceed2b078c0955ce1b8509631369dab20e1a952180a9ea5fae87b3895fba98c2b138c336ccfba886b0823fd774415ccc9394ae159"
var client *mongo.Client

func init() {
	// Inisialisasi koneksi MongoDB
	clientOptions := options.Client().ApplyURI("mongodb+srv://MigrasiData:Salman123456.@cluster0.ot8qmry.mongodb.net/")
	client, _ = mongo.Connect(context.Background(), clientOptions)
}
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metode tidak diizinkan", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Retrieve hashed password from MongoDB based on the username
	hashedPassword, err := getHashedPassword(username)
	if err != nil {
		http.Error(w, "Gagal mencari kredensial", http.StatusUnauthorized)
		return
	}

	// Compare the provided password with the hashed password
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		http.Error(w, "Login gagal", http.StatusUnauthorized)
		return
	}

	// If login is successful, generate a PASETO token
	tokenString, _ := watoken.Encode(username, Privatekey)

	// Set the token as a cookie
	cookie := http.Cookie{
		Name:     "token",     // Nama cookie
		Value:    tokenString, // Token sebagai nilai cookie
		HttpOnly: true,        // Hanya bisa diakses melalui HTTP
		Path:     "/",         // Path di mana cookie berlaku (misalnya, seluruh situs)
		MaxAge:   3600,        // Durasi cookie (dalam detik), sesuaikan sesuai kebutuhan
		// Secure: true, // Jika situs dijalankan melalui HTTPS
	}

	http.SetCookie(w, &cookie) // Set cookie dalam respons

	// Prepare JSON response
	response := map[string]interface{}{
		"message":  "Login berhasil",
		"token":    tokenString,
		"username": username,
		// It's not recommended to include the password in the response
	}

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Function to retrieve hashed password from MongoDB
// Function to retrieve hashed password from MongoDB
func getHashedPassword(username string) (string, error) {
	// Mendapatkan koneksi ke koleksi Users di database MongoDB
	collection := client.Database("InformasiWisataBandung").Collection("Users")

	// Mencari dokumen berdasarkan username
	filter := bson.M{"username": username}
	var user User

	err := collection.FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		// Tangani kesalahan, termasuk jika pengguna tidak ditemukan.
		if err == mongo.ErrNoDocuments {
			// Jika pengguna tidak ditemukan, kembalikan pesan kesalahan yang sesuai.
			return "", fmt.Errorf("Pengguna dengan username %s tidak ditemukan", username)
		}
		// Jika terjadi kesalahan lain, kembalikan pesan kesalahan.
		return "", err
	}

	// Mengembalikan kata sandi terenkripsi dari dokumen pengguna yang sesuai
	return user.Password, nil
}
