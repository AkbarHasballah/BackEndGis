package BEGis

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func GCFHandler(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datagedung := GetAllUser(mconn, collectionname)
	return GCFReturnStruct(datagedung)
}

func GCFFindUserByID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}
	user := FindUser(mconn, collectionname, datauser)
	return GCFReturnStruct(user)
}

func GCFFindUserByName(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}

	// Jika username kosong, maka respon "false" dan data tidak ada
	if datauser.Username == "" {
		return "false"
	}

	// Jika ada username, mencari data pengguna
	user := FindUserUser(mconn, collectionname, datauser)

	// Jika data pengguna ditemukan, mengembalikan data pengguna dalam format yang sesuai
	if user != (User{}) {
		return GCFReturnStruct(user)
	}

	// Jika tidak ada data pengguna yang ditemukan, mengembalikan "false" dan data tidak ada
	return "false"
}

func GCFDeleteHandler(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}
	DeleteUser(mconn, collectionname, datauser)
	return GCFReturnStruct(datauser)
}

func GCFUpdateHandler(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}
	ReplaceOneDoc(mconn, collectionname, bson.M{"username": datauser.Username}, datauser)
	return GCFReturnStruct(datauser)
}

// add encrypt password to database and tokenstring
// func GCFCreateHandler(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {

// 	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
// 	var datauser User
// 	err := json.NewDecoder(r.Body).Decode(&datauser)
// 	if err != nil {
// 		return err.Error()
// 	}
// 	CreateNewUserRole(mconn, collectionname, datauser)
// 	return GCFReturnStruct(datauser)
// }

func GCFCreateHandlerTokenPaseto(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}
	hashedPassword, hashErr := HashPassword(datauser.Password)
	if hashErr != nil {
		return hashErr.Error()
	}
	datauser.Password = hashedPassword
	CreateNewUserRole(mconn, collectionname, datauser)
	tokenstring, err := watoken.Encode(datauser.Username, os.Getenv(PASETOPRIVATEKEYENV))
	if err != nil {
		return err.Error()
	}
	datauser.Token = tokenstring
	return GCFReturnStruct(datauser)
}

func GCFCreateHandler(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}

	// Hash the password before storing it
	hashedPassword, hashErr := HashPassword(datauser.Password)
	if hashErr != nil {
		return hashErr.Error()
	}
	datauser.Password = hashedPassword

	createErr := CreateNewUserRole(mconn, collectionname, datauser)
	fmt.Println(createErr)

	return GCFReturnStruct(datauser)
}
func GFCPostHandlerUser(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	var Response Credential
	Response.Status = false

	// Mendapatkan data yang diterima dari permintaan HTTP POST
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		Response.Message = "error parsing application/json: " + err.Error()
	} else {
		// Menggunakan variabel MONGOCONNSTRINGENV untuk string koneksi MongoDB
		mongoConnStringEnv := MONGOCONNSTRINGENV

		mconn := SetConnection(mongoConnStringEnv, dbname)

		// Lakukan pemeriksaan kata sandi menggunakan bcrypt
		if IsPasswordValid(mconn, collectionname, datauser) {
			Response.Status = true
			Response.Message = "Selamat Datang"
		} else {
			Response.Message = "Password Salah"
		}
	}

	// Mengirimkan respons sebagai JSON
	responseJSON, _ := json.Marshal(Response)
	return string(responseJSON)
}

func GCFPostHandler(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	var Response Credential
	Response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		Response.Message = "error parsing application/json: " + err.Error()
	} else {
		if IsPasswordValid(mconn, collectionname, datauser) {
			Response.Status = true
			tokenstring, err := watoken.Encode(datauser.Username, os.Getenv(PASETOPRIVATEKEYENV))
			if err != nil {
				Response.Message = "Gagal Encode Token : " + err.Error()
			} else {
				Response.Message = "Selamat Datang"
				Response.Token = tokenstring
			}
		} else {
			Response.Message = "Password Salah"
		}
	}

	return GCFReturnStruct(Response)
}

func GCFReturnStruct(DataStuct any) string {
	jsondata, _ := json.Marshal(DataStuct)
	return string(jsondata)
}

// product
func GCFGetAllProduct(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datagedung := GetAllProduct(mconn, collectionname)
	return GCFReturnStruct(datagedung)
}

func GCFCreateProduct(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var dataproduct Product
	err := json.NewDecoder(r.Body).Decode(&dataproduct)
	if err != nil {
		return err.Error()
	}
	CreateNewProduct(mconn, collectionname, dataproduct)
	return GCFReturnStruct(dataproduct)
}

func GCFLoginTest(username, password, MONGOCONNSTRINGENV, dbname, collectionname string) bool {
	// Membuat koneksi ke MongoDB
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Mencari data pengguna berdasarkan username
	filter := bson.M{"username": username}
	collection := collectionname
	res := atdb.GetOneDoc[User](mconn, collection, filter)

	// Memeriksa apakah pengguna ditemukan dalam database
	if res == (User{}) {
		return false
	}

	// Memeriksa apakah kata sandi cocok
	return CheckPasswordHash(password, res.Password)
}

// ...

// Fungsi untuk mencari jalan terdekat
func FindNearestRoad(mconn *mongo.Database, collectionname string, coordinates []float64) GeoJsonLineString {
	// Gunakan query $near di MongoDB untuk mencari jalan terdekat
	filter := bson.M{
		"geometry.coordinates": bson.M{
			"$near": bson.M{
				"$geometry": bson.M{
					"type":        "Point",
					"coordinates": coordinates,
				},
			},
		},
	}

	var result GeoJsonLineString
	err := mconn.Collection(collectionname).FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		log.Fatal(err)
	}

	return result
}

// Fungsi untuk mencari jalur dari jalan awal ke jalan akhir
// Fungsi untuk mencari jalur dari jalan awal ke jalan akhir
func FindRoute(mconn *mongo.Database, collectionname string, startGeometry, endGeometry GeometryLineString) []GeoJsonLineString {
	var result []GeoJsonLineString

	// Mencari jalan berdasarkan geometri awal
	startRoadFilter := bson.M{
		"geometry.coordinates": bson.M{
			"$near": bson.M{
				"$geometry": startGeometry,
			},
		},
	}

	var startRoad GeoJsonLineString
	err := mconn.Collection(collectionname).FindOne(context.Background(), startRoadFilter).Decode(&startRoad)
	if err != nil {
		log.Fatal(err)
	}

	// Mencari jalan berdasarkan geometri akhir
	endRoadFilter := bson.M{
		"geometry.coordinates": bson.M{
			"$near": bson.M{
				"$geometry": endGeometry,
			},
		},
	}

	var endRoad GeoJsonLineString
	err = mconn.Collection(collectionname).FindOne(context.Background(), endRoadFilter).Decode(&endRoad)
	if err != nil {
		log.Fatal(err)
	}

	// Mengembalikan hasil pencarian
	result = append(result, startRoad, endRoad)

	return result
}

// Handler untuk endpoint jalan terdekat
func GCFNearestRoadHandler(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	// Validasi token di sini (gunakan func untuk validasi token)

	// Mendapatkan koordinat dari request
	var coordinates []float64
	err := json.NewDecoder(r.Body).Decode(&coordinates)
	if err != nil {
		return err.Error()
	}

	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	result := FindNearestRoad(mconn, collectionname, coordinates)

	return GCFReturnStruct(result)
}

// Handler untuk endpoint jalur
// Handler untuk endpoint jalur
func GCFRouteHandler(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	// Validasi token di sini (gunakan func untuk validasi token)

	// Mendapatkan inputan jalan awal dan jalan akhir
	var startGeometry, endGeometry GeometryLineString
	err := json.NewDecoder(r.Body).Decode(&struct {
		StartGeometry GeometryLineString `json:"startGeometry"`
		EndGeometry   GeometryLineString `json:"endGeometry"`
	}{
		StartGeometry: startGeometry,
		EndGeometry:   endGeometry,
	})
	if err != nil {
		return err.Error()
	}

	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	route := FindRoute(mconn, collectionname, startGeometry, endGeometry)

	return GCFReturnStruct(route)
}

// FUNCTION SIGN TOKEN TAKISS

func GCFPostHandlerSIGN(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request, w http.ResponseWriter) {
	var Response Credential
	Response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		Response.Message = "error parsing application/json: " + err.Error()
	} else {
		if IsPasswordValid(mconn, collectionname, datauser) {
			Response.Status = true
			tokenstring, err := watoken.Encode(datauser.Username, os.Getenv(PASETOPRIVATEKEYENV))
			if err != nil {
				Response.Message = "Gagal Encode Token : " + err.Error()
			} else {
				Response.Message = "Selamat Datang"
				Response.Token = tokenstring

				// Set the token as a cookie
				cookie := http.Cookie{
					Name:     "token",     // Cookie name
					Value:    tokenstring, // Token as cookie value
					HttpOnly: true,        // Can only be accessed via HTTP
					Path:     "/",         // Path where the cookie is valid (e.g., the entire site)
					MaxAge:   3600,        // Cookie duration (in seconds), adjust as needed
					Secure:   true,        // If the site is served over HTTPS
				}

				http.SetCookie(w, &cookie) // Set cookie in the response

				// Prepare JSON response
				response := map[string]interface{}{
					"message":  "Login berhasil",
					"token":    tokenstring,
					"username": datauser.Username,
					// It's not recommended to include the password in the response
				}

				// Send JSON response
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
				return
			}
		} else {
			Response.Message = "Password Salah"
		}
	}

	// If the function reaches here, it means there was an error or invalid password
	// Prepare JSON response for error case
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(Response)
}
func CreateWisata(MONGOCONNSTRING, dbname, collectionname string, tempat TempatWisata) error {
	clientOptions := options.Client().ApplyURI(MONGOCONNSTRING)
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return err
	}
	defer client.Disconnect(context.TODO())

	collection := client.Database(dbname).Collection(collectionname)

	_, err = collection.InsertOne(context.TODO(), tempat)
	if err != nil {
		return err
	}

	return nil
}
func ReadWisata(MONGOCONNSTRING, dbname, collectionname string) ([]TempatWisata, error) {
	clientOptions := options.Client().ApplyURI(MONGOCONNSTRING)
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return nil, err
	}
	defer client.Disconnect(context.TODO())

	collection := client.Database(dbname).Collection(collectionname)

	cursor, err := collection.Find(context.TODO(), bson.D{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var tempatList []TempatWisata

	for cursor.Next(context.TODO()) {
		var tempat TempatWisata
		err := cursor.Decode(&tempat)
		if err != nil {
			return nil, err
		}
		tempatList = append(tempatList, tempat)
	}

	return tempatList, nil
}
func UpdateWisata(MONGOCONNSTRING, dbname, collectionname string, filter bson.D, update bson.D) error {
	clientOptions := options.Client().ApplyURI(MONGOCONNSTRING)
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return err
	}
	defer client.Disconnect(context.TODO())

	collection := client.Database(dbname).Collection(collectionname)

	_, err = collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		return err
	}

	return nil
}
func DeleteWisata(MONGOCONNSTRING, dbname, collectionname string, filter bson.D) error {
	clientOptions := options.Client().ApplyURI(MONGOCONNSTRING)
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return err
	}
	defer client.Disconnect(context.TODO())

	collection := client.Database(dbname).Collection(collectionname)

	_, err = collection.DeleteOne(context.TODO(), filter)
	if err != nil {
		return err
	}

	return nil
}
func InsertDataUserGCF(Mongoenv, dbname string, r *http.Request) string {
	resp := new(Credential)
	userdata := new(User)
	resp.Status = false
	conn := SetConnection(Mongoenv, dbname)
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		resp.Message = "error parsing application/json: " + err.Error()
	} else {
		resp.Status = true
		hash, err := HashPassword(userdata.Password)
		if err != nil {
			resp.Message = "Gagal Hash Password" + err.Error()
		}
		InsertUserdata(conn, userdata.Username, userdata.Role, hash)
		resp.Message = "Berhasil Input data"
	}
	return GCFReturnStruct(resp)
}

// Content

func GCFCreateContent(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datacontent Content
	err := json.NewDecoder(r.Body).Decode(&datacontent)
	if err != nil {
		return err.Error()
	}

	CreateNewContent(mconn, collectionname, datacontent)
	// setelah create content munculkan response berhasil dan 200

	if CreateResponse(true, "Berhasil", datacontent) != (Response{}) {
		return GCFReturnStruct(CreateResponse(true, "success Create Data Content", datacontent))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Create Data Content", datacontent))
	}
}

func GCFDeleteHandlerContent(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var contentdata Content
	err := json.NewDecoder(r.Body).Decode(&contentdata)
	if err != nil {
		return err.Error()
	}
	DeleteContent(mconn, collectionname, contentdata)
	return GCFReturnStruct(contentdata)
}

func GCFUpdatedContent(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var contentdata Content
	err := json.NewDecoder(r.Body).Decode(&contentdata)
	if err != nil {
		return err.Error()
	}
	ReplaceContent(mconn, collectionname, bson.M{"id": contentdata.ID}, contentdata)
	return GCFReturnStruct(contentdata)
}

func GCFCreateNewBlog(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var blogdata Blog
	err := json.NewDecoder(r.Body).Decode(&blogdata)
	if err != nil {
		return err.Error()
	}
	CreateNewBlog(mconn, collectionname, blogdata)
	return GCFReturnStruct(blogdata)
}

func GCFFindContentAllID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Inisialisasi variabel datacontent
	var datacontent Content

	// Membaca data JSON dari permintaan HTTP ke dalam datacontent
	err := json.NewDecoder(r.Body).Decode(&datacontent)
	if err != nil {
		return err.Error()
	}

	// Memanggil fungsi FindContentAllId
	content := FindContentAllId(mconn, collectionname, datacontent)

	// Mengembalikan hasil dalam bentuk JSON
	return GCFReturnStruct(content)
}

func GCFFindBlogAllID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Inisialisasi variabel datacontent
	var datablog Blog

	// Membaca data JSON dari permintaan HTTP ke dalam datacontent
	err := json.NewDecoder(r.Body).Decode(&datablog)
	if err != nil {
		return err.Error()
	}

	// Memanggil fungsi FindContentAllId
	blog := GetIDBlog(mconn, collectionname, datablog)

	// Mengembalikan hasil dalam bentuk JSON
	return GCFReturnStruct(blog)
}

func GCFGetAllBlog(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datablog := GetAllBlogAll(mconn, collectionname)
	return GCFReturnStruct(datablog)
}

func GCFCreateTokenAndSaveToDB(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) (string, error) {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Inisialisasi variabel datauser
	var datauser User

	// Membaca data JSON dari permintaan HTTP ke dalam datauser
	if err := json.NewDecoder(r.Body).Decode(&datauser); err != nil {
		return "", err // Mengembalikan kesalahan langsung
	}

	// Generate a token for the user
	tokenstring, err := watoken.Encode(datauser.Username, os.Getenv(PASETOPRIVATEKEYENV))
	if err != nil {
		return "", err // Mengembalikan kesalahan langsung
	}
	datauser.Token = tokenstring

	// Simpan pengguna ke dalam basis data
	if err := atdb.InsertOneDoc(mconn, collectionname, datauser); err != nil {
		return tokenstring, nil // Mengembalikan kesalahan langsung
	}

	return tokenstring, nil // Mengembalikan token dan nil untuk kesalahan jika sukses
}
func GCFCreteRegister(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var userdata User
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		return err.Error()
	}
	CreateUser(mconn, collectionname, userdata)
	return GCFReturnStruct(userdata)
}

func GCFLoginAfterCreate(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var userdata User
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		return err.Error()
	}
	if IsPasswordValid(mconn, collectionname, userdata) {
		tokenstring, err := watoken.Encode(userdata.Username, os.Getenv("PASETOPRIVATEKEYENV"))
		if err != nil {
			return err.Error()
		}
		userdata.Token = tokenstring
		return GCFReturnStruct(userdata)
	} else {
		return "Password Salah"
	}
}

func GCFLoginAfterCreater(MONGOCONNSTRINGENV, dbname, collectionname, privateKeyEnv string, r *http.Request) (string, error) {
	// Ambil data pengguna dari request, misalnya dari body JSON atau form data.
	var userdata User
	// Implement the logic to extract user data from the request (r) here.

	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Lakukan otentikasi pengguna yang baru saja dibuat.
	token, err := AuthenticateUserAndGenerateToken(privateKeyEnv, mconn, collectionname, userdata)
	if err != nil {
		return "", err
	}
	return token, nil
}

func GCFLoginAfterCreatee(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var userdata User
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		return err.Error()
	}
	if IsPasswordValid(mconn, collectionname, userdata) {
		// Password is valid, return a success message or some other response.
		return "Login successful"

	} else {
		// Password is not valid, return an error message.
		return "Password Salah"
	}
}

func GCFLoginAfterCreateee(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var userdata User
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		return err.Error()
	}
	if IsPasswordValid(mconn, collectionname, userdata) {
		// Password is valid, construct and return the GCFReturnStruct.
		response := CreateResponse(true, "Berhasil Login", userdata)
		return GCFReturnStruct(response) // Return GCFReturnStruct directly
	} else {
		// Password is not valid, return an error message.
		return "Password Salah"
	}
}
func GCFLoginAfterCreateeee(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var userdata User
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		return err.Error()
	}
	if IsPasswordValid(mconn, collectionname, userdata) {
		// Password is valid, return a success message or some other response.
		return GCFReturnStruct(userdata)
	} else {
		// Password is not valid, return an error message.
		return "Password Salah"
	}
}

func GCFCreteCommnet(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var commentdata Comment
	err := json.NewDecoder(r.Body).Decode(&commentdata)
	if err != nil {
		return err.Error()
	}

	if err := CreateComment(mconn, collectionname, commentdata); err != nil {
		return GCFReturnStruct(CreateResponse(true, "Succes Create Comment", commentdata))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Create Comment", commentdata))
	}
}

func GCFGetAllComment(MONGOCONNSTRINGENV, dbname, collectionname string) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	datacomment := GetAllComment(mconn, collectionname)
	if datacomment != nil {
		return GCFReturnStruct(CreateResponse(true, "success Get All Comment", datacomment))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Get All Comment", datacomment))
	}
}
func GFCUpadatedCommnet(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var commentdata Comment
	err := json.NewDecoder(r.Body).Decode(&commentdata)
	if err != nil {
		return err.Error()
	}

	if err := UpdatedComment(mconn, collectionname, bson.M{"id": commentdata.ID}, commentdata); err != nil {
		return GCFReturnStruct(CreateResponse(true, "Success Updated Comment", commentdata))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Updated Comment", commentdata))
	}
}

func GCFDeletedCommnet(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var commentdata Comment
	if err := json.NewDecoder(r.Body).Decode(&commentdata); err != nil {
		return GCFReturnStruct(CreateResponse(false, "Failed to process request", commentdata))
	}

	if err := DeleteComment(mconn, collectionname, commentdata); err != nil {
		return GCFReturnStruct(CreateResponse(true, "Successfully deleted comment", commentdata))
	}

	return GCFReturnStruct(CreateResponse(false, "Failed to delete comment", commentdata))
}

func GCFCreatePostLineStringg(MONGOCONNSTRINGENV, dbname, collection string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var geojsonline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&geojsonline)
	if err != nil {
		return err.Error()
	}

	// Mengambil nilai header PASETO dari permintaan HTTP
	pasetoValue := r.Header.Get("PASETOPRIVATEKEYENV")

	// Disini Anda dapat menggunakan nilai pasetoValue sesuai kebutuhan Anda
	// Misalnya, menggunakannya untuk otentikasi atau enkripsi.
	// Contoh sederhana menambahkan nilainya ke dalam pesan respons:
	response := GCFReturnStruct(geojsonline)
	response += " PASETO value: " + pasetoValue

	PostLinestring(mconn, collection, geojsonline)
	return response
}

func GCFCreatePostLineString(MONGOCONNSTRINGENV, dbname, collection string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var geojsonline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&geojsonline)
	if err != nil {
		return err.Error()
	}
	PostLinestring(mconn, collection, geojsonline)
	return GCFReturnStruct(geojsonline)
}

func GCFDeleteLineString(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var dataline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&dataline)
	if err != nil {
		return err.Error()
	}

	if err := DeleteLinestring(mconn, collectionname, dataline); err != nil {
		return GCFReturnStruct(CreateResponse(true, "Success Delete LineString", dataline))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Delete LineString", dataline))
	}
}

func GCFUpdateLinestring(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var dataline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&dataline)
	if err != nil {
		return err.Error()
	}

	if err := UpdatedLinestring(mconn, collectionname, bson.M{"properties.coordinates": dataline.Geometry.Coordinates}, dataline); err != nil {
		return GCFReturnStruct(CreateResponse(true, "Success Update LineString", dataline))
	} else {
		return GCFReturnStruct(CreateResponse(false, "Failed Update LineString", dataline))
	}
}

func GCFCreateLineStringgg(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	// MongoDB Connection Setup
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Parsing Request Body
	var dataline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&dataline)
	if err != nil {
		return err.Error()
	}

	if r.Header.Get("Secret") == os.Getenv("SECRET") {
		// Handling Authorization
		err := PostLinestring(mconn, collectionname, dataline)
		if err != nil {
			// Success
			return GCFReturnStruct(CreateResponse(true, "Success: LineString created", dataline))
		} else {
			return GCFReturnStruct(CreateResponse(false, "Error", nil))
		}
	} else {
		return GCFReturnStruct(CreateResponse(false, "Unauthorized: Secret header does not match", nil))
	}

	// This part is unreachable, so you might want to remove it
	// return GCFReturnStruct(CreateResponse(false, "Success to create LineString", nil))
}

func GCFCreatePolygone(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	// MongoDB Connection Setup
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Parsing Request Body
	var datapolygone GeoJsonPolygon
	err := json.NewDecoder(r.Body).Decode(&datapolygone)
	if err != nil {
		return err.Error()
	}

	// Handling Authorization
	if err := PostPolygone(mconn, collectionname, datapolygone); err != nil {
		// Success
		return GCFReturnStruct(CreateResponse(true, "Success Create Polygone", datapolygone))
	} else {
		// Failure
		return GCFReturnStruct(CreateResponse(false, "Failed Create Polygone", datapolygone))
	}
}

func GCFPoint(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datapoint GeometryPoint

	// Decode the request body
	if err := json.NewDecoder(r.Body).Decode(&datapoint); err != nil {
		log.Printf("Error decoding request body: %v", err)
		return GCFReturnStruct(CreateResponse(false, "Bad Request: Invalid JSON", nil))
	}

	// Check for the "Secret" header
	secretHeader := r.Header.Get("Secret")
	expectedSecret := os.Getenv("SECRET")

	if secretHeader != expectedSecret {
		log.Printf("Unauthorized: Secret header does not match. Expected: %s, Actual: %s", expectedSecret, secretHeader)
		return GCFReturnStruct(CreateResponse(false, "Unauthorized: Secret header does not match", nil))
	}

	// Attempt to post the data point to MongoDB
	if err := PostPoint(mconn, collectionname, datapoint); err != nil {
		log.Printf("Error posting data point to MongoDB: %v", err)
		return GCFReturnStruct(CreateResponse(false, "Failed to create point", nil))
	}

	log.Println("Success: Point created")
	return GCFReturnStruct(CreateResponse(true, "Success: Point created", datapoint))
}

func GCFlineStingCreate(MONGOCONNSTRINGENV, dbname, collection string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var geojsonline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&geojsonline)
	if err != nil {
		return err.Error()
	}
	PostLinestring(mconn, collection, geojsonline)
	return GCFReturnStruct(geojsonline)
}

func GCFlineStingCreatea(MONGOCONNSTRINGENV, dbname, collection string, r *http.Request) string {
	// MongoDB Connection Setup
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Parsing Request Body
	var geojsonline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&geojsonline)
	if err != nil {
		return GCFReturnStruct(CreateResponse(false, "Bad Request: Invalid JSON", nil))
	}

	// Checking Secret Header
	secretHeader := r.Header.Get("Secret")
	expectedSecret := os.Getenv("SECRET")

	if secretHeader != expectedSecret {
		log.Printf("Unauthorized: Secret header does not match. Expected: %s, Actual: %s", expectedSecret, secretHeader)
		return GCFReturnStruct(CreateResponse(false, "Unauthorized: Secret header does not match", nil))
	}

	// Handling Authorization
	PostLinestring(mconn, collection, geojsonline)

	return GCFReturnStruct(CreateResponse(true, "Success: LineString created", geojsonline))
}

func GCFCreatePolygonee(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	// MongoDB Connection Setup
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Parsing Request Body
	var datapolygone GeoJsonPolygon
	err := json.NewDecoder(r.Body).Decode(&datapolygone)
	if err != nil {
		return GCFReturnStruct(CreateResponse(false, "Bad Request: Invalid JSON", nil))
	}

	// Checking Secret Header
	secretHeader := r.Header.Get("Secret")
	expectedSecret := os.Getenv("SECRET")

	if secretHeader != expectedSecret {
		log.Printf("Unauthorized: Secret header does not match. Expected: %s, Actual: %s", expectedSecret, secretHeader)
		return GCFReturnStruct(CreateResponse(false, "Unauthorized: Secret header does not match", nil))
	}

	// Handling Authorization
	if err := PostPolygone(mconn, collectionname, datapolygone); err != nil {
		log.Printf("Error creating polygon: %v", err)
		return GCFReturnStruct(CreateResponse(false, "Failed Create Polygone", nil))
	}

	log.Println("Success: Polygon created")
	return GCFReturnStruct(CreateResponse(true, "Success Create Polygone", datapolygone))
}
