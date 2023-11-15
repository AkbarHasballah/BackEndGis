package BEGis

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func SetConnection(MONGOCONNSTRINGENV, dbname string) *mongo.Database {
	var DBmongoinfo = atdb.DBInfo{
		DBString: os.Getenv(MONGOCONNSTRINGENV),
		DBName:   dbname,
	}
	return atdb.MongoConnect(DBmongoinfo)
}

func GetAllBangunanLineString(mongoconn *mongo.Database, collection string) []GeoJson {
	lokasi := atdb.GetAllDoc[[]GeoJson](mongoconn, collection)
	return lokasi
}

func GetAllProduct(mongoconn *mongo.Database, collection string) []Product {
	product := atdb.GetAllDoc[[]Product](mongoconn, collection)
	return product
}

func GetNameAndPassowrd(mongoconn *mongo.Database, collection string) []User {
	user := atdb.GetAllDoc[[]User](mongoconn, collection)
	return user
}

func GetAllUser(mongoconn *mongo.Database, collection string) []User {
	user := atdb.GetAllDoc[[]User](mongoconn, collection)
	return user
}
func CreateNewUserRole(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}
func CreateUserAndAddedToeken(PASETOPRIVATEKEYENV string, mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Insert the user data into the database
	atdb.InsertOneDoc(mongoconn, collection, userdata)

	// Create a token for the user
	tokenstring, err := watoken.Encode(userdata.Username, os.Getenv(PASETOPRIVATEKEYENV))
	if err != nil {
		return err
	}
	userdata.Token = tokenstring

	// Update the user data in the database
	return atdb.ReplaceOneDoc(mongoconn, collection, bson.M{"username": userdata.Username}, userdata)
}

func DeleteUser(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	filter := bson.M{"username": userdata.Username}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}
func ReplaceOneDoc(mongoconn *mongo.Database, collection string, filter bson.M, userdata User) interface{} {
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, userdata)
}
func FindUser(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{"username": userdata.Username}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}

func FindUserUser(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{
		"username": userdata.Username,
	}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}

func IsPasswordValid(mongoconn *mongo.Database, collection string, userdata User) bool {
	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[User](mongoconn, collection, filter)
	return CheckPasswordHash(userdata.Password, res.Password)
}
func CreateNewProduct(mongoconn *mongo.Database, collection string, productdata Product) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, productdata)
}

func InsertUserdata(MongoConn *mongo.Database, username, role, password string) (InsertedID interface{}) {
	req := new(User)
	req.Username = username
	req.Password = password
	req.Role = role
	return InsertOneDoc(MongoConn, "user", req)
}
func InsertOneDoc(db *mongo.Database, collection string, doc interface{}) (insertedID interface{}) {
	insertResult, err := db.Collection(collection).InsertOne(context.TODO(), doc)
	if err != nil {
		fmt.Printf("InsertOneDoc: %v\n", err)
	}
	return insertResult.InsertedID
}

// gis function

// content
func CreateNewContent(mongoconn *mongo.Database, collection string, contentdata Content) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, contentdata)
}

func DeleteContent(mongoconn *mongo.Database, collection string, contentdata Content) interface{} {
	filter := bson.M{"id": contentdata.ID}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func ReplaceContent(mongoconn *mongo.Database, collection string, filter bson.M, contentdata Content) interface{} {
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, contentdata)
}

func CreateNewBlog(mongoconn *mongo.Database, collection string, blogdata Blog) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, blogdata)
}

func FindContentAllId(mongoconn *mongo.Database, collection string, contentdata Content) Content {
	filter := bson.M{"id": contentdata.ID}
	return atdb.GetOneDoc[Content](mongoconn, collection, filter)
}

func GetAllBlogAll(mongoconn *mongo.Database, collection string) []Blog {
	blog := atdb.GetAllDoc[[]Blog](mongoconn, collection)
	return blog
}

func GetIDBlog(mongoconn *mongo.Database, collection string, blogdata Blog) Blog {
	filter := bson.M{"id": blogdata.ID}
	return atdb.GetOneDoc[Blog](mongoconn, collection, filter)
}

func CreateUserAndAddToken(privateKeyEnv string, mongoconn *mongo.Database, collection string, userdata User) error {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Create a token for the user
	tokenstring, err := watoken.Encode(userdata.Username, os.Getenv(privateKeyEnv))
	if err != nil {
		return err
	}

	userdata.Token = tokenstring

	// Insert the user data into the MongoDB collection
	if err := atdb.InsertOneDoc(mongoconn, collection, userdata.Username); err != nil {
		return nil // Mengembalikan kesalahan yang dikembalikan oleh atdb.InsertOneDoc
	}

	// Return nil to indicate success
	return nil
}

func AuthenticateUserAndGenerateToken(privateKeyEnv string, mongoconn *mongo.Database, collection string, userdata User) (string, error) {
	// Cari pengguna berdasarkan nama pengguna
	username := userdata.Username
	password := userdata.Password
	userdata, err := FindUserByUsername(mongoconn, collection, username)
	if err != nil {
		return "", err
	}

	// Memeriksa kata sandi
	if !CheckPasswordHash(password, userdata.Password) {
		return "", errors.New("Password salah") // Gantilah pesan kesalahan sesuai kebutuhan Anda
	}

	// Generate token untuk otentikasi
	tokenstring, err := watoken.Encode(username, os.Getenv(privateKeyEnv))
	if err != nil {
		return "", err
	}

	return tokenstring, nil
}

func FindUserByUsername(mongoconn *mongo.Database, collection string, username string) (User, error) {
	var user User
	filter := bson.M{"username": username}
	err := mongoconn.Collection(collection).FindOne(context.TODO(), filter).Decode(&user)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// create login using Private
func CreateLogin(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword
	// Create a token for the user
	tokenstring, err := watoken.Encode(userdata.Username, userdata.Private)
	if err != nil {
		return err
	}
	userdata.Token = tokenstring

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}

func CreateComment(mongoconn *mongo.Database, collection string, commentdata Comment) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, commentdata)
}

func DeleteComment(mongoconn *mongo.Database, collection string, commentdata Comment) interface{} {
	filter := bson.M{"id": commentdata.ID}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedComment(mongoconn *mongo.Database, collection string, filter bson.M, commentdata Comment) interface{} {
	filter = bson.M{"id": commentdata.ID}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, commentdata)
}

func GetAllComment(mongoconn *mongo.Database, collection string) []Comment {
	comment := atdb.GetAllDoc[[]Comment](mongoconn, collection)
	return comment
}

func PostLineString(mongoconn *mongo.Database, collection string, commentdata GeoJsonLineString) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, commentdata)
}

func PostLinestring(mongoconn *mongo.Database, collection string, linestringdata GeoJsonLineString) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, linestringdata)
}

func GetByCoordinate(mongoconn *mongo.Database, collection string, linestringdata GeoJsonLineString) GeoJsonLineString {
	filter := bson.M{"geometry.coordinates": linestringdata.Geometry.Coordinates}
	return atdb.GetOneDoc[GeoJsonLineString](mongoconn, collection, filter)
}

func DeleteLinestring(mongoconn *mongo.Database, collection string, linestringdata GeoJsonLineString) interface{} {
	filter := bson.M{"geometry.coordinates": linestringdata.Geometry.Coordinates}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedLinestring(mongoconn *mongo.Database, collection string, filter bson.M, linestringdata GeoJsonLineString) interface{} {
	filter = bson.M{"geometry.coordinates": linestringdata.Geometry.Coordinates}
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, linestringdata)
}

func PostPolygone(mongoconn *mongo.Database, collection string, polygonedata GeoJsonPolygon) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, polygonedata)
}

func PostPoint(mongoconn *mongo.Database, collection string, pointdata GeometryPoint) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, pointdata)
}
