package BEGis

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
)
func GCFPostkordinatCoy(Mongostring, Publickey, dbname, colname string, r *http.Request) string {
	req := new(Credents)
	conn := GetConnectionMongo(Mongostring, dbname)
	resp := new(LonLatProperties)
	err := json.NewDecoder(r.Body).Decode(&resp)
	tokenlogin := r.Header.Get("Login")
	if tokenlogin == "" {
		req.Status = strconv.Itoa(http.StatusNotFound)
		req.Message = "Header Login Not Exist"
	} else {
		existing := IsExist(tokenlogin, os.Getenv(Publickey))
		if !existing {
			req.Status = strconv.Itoa(http.StatusNotFound)
			req.Message = "Kamu kayaknya belum punya akun"
		} else {
			if err != nil {
				req.Status = strconv.Itoa(http.StatusNotFound)
				req.Message = "error parsing application/json: " + err.Error()
			} else {
				req.Status = strconv.Itoa(http.StatusOK)
				Ins := InsertDataLonlat(conn, colname,
					resp.Coordinates,
					resp.Name,
					resp.Volume,
					resp.Type)
				req.Message = fmt.Sprintf("%v:%v", "Berhasil Input data", Ins)
			}
		}
	}
	return ReturnStringStruct(req)
}

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
