package BEGis

type GeometryPolygon struct {
	Coordinates [][][]float64 `json:"coordinates" bson:"coordinates"`
	Type        string        `json:"type" bson:"type"`
}

type GeometryLineString struct {
	Coordinates [][]float64 `json:"coordinates" bson:"coordinates"`
	Type        string      `json:"type" bson:"type"`
}

type GeometryPoint struct {
	Coordinates []float64 `json:"coordinates" bson:"coordinates"`
	Type        string    `json:"type" bson:"type"`
}

type GeoJsonLineString struct {
	Type       string             `json:"type" bson:"type"`
	Properties Properties         `json:"properties" bson:"properties"`
	Geometry   GeometryLineString `json:"geometry" bson:"geometry"`
}

type GeoJsonPolygon struct {
	Type       string          `json:"type" bson:"type"`
	Properties Properties      `json:"properties" bson:"properties"`
	Geometry   GeometryPolygon `json:"geometry" bson:"geometry"`
}

type Geometry struct {
	Coordinates interface{} `json:"coordinates" bson:"coordinates"`
	Type        string      `json:"type" bson:"type"`
}
type GeoJson struct {
	Type       string     `json:"type" bson:"type"`
	Properties Properties `json:"properties" bson:"properties"`
	Geometry   Geometry   `json:"geometry" bson:"geometry"`
}

type Properties struct {
	Name string `json:"name" bson:"name"`
}

type User struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
	Role     string `json:"role,omitempty" bson:"role,omitempty"`
	Token    string `json:"token,omitempty" bson:"token,omitempty"`
	Private  string `json:"private,omitempty" bson:"private,omitempty"`
	Publick  string `json:"publick,omitempty" bson:"publick,omitempty"`
}

type Credential struct {
	Status  bool   `json:"status" bson:"status"`
	Token   string `json:"token,omitempty" bson:"token,omitempty"`
	Message string `json:"message,omitempty" bson:"message,omitempty"`
}

type Product struct {
	Nomorid     int    `json:"nomorid" bson:"nomorid"`
	Name        string `json:"name" bson:"name"`
	Description string `json:"description" bson:"description"`
	Price       int    `json:"price" bson:"price"`
	Stock       int    `json:"stock" bson:"stock"`
	Size        string `json:"size" bson:"size"`
	Image       string `json:"image" bson:"image"`
}

type Response struct {
	Status  bool        `json:"status" bson:"status"`
	Message string      `json:"message" bson:"message"`
	Data    interface{} `json:"data" bson:"data"`
}
type TempatWisata struct {
	Nama      string  `json:"nama"`
	Jenis     string  `json:"jenis"`
	Deskripsi string  `json:"deskripsi"`
	Lokasi    Lokasi  `json:"lokasi"`
	Alamat    string  `json:"alamat"`
	Gambar    string  `json:"gambar"`
	Rating    float64 `json:"rating"`
}

type Lokasi struct {
	Type        string    `json:"type"`
	Coordinates []float64 `json:"coordinates"`
}
type Blog struct {
	ID          int       `json:"id" bson:"id"`
	Title       string    `json:"title" bson:"title"`
	Tanggal     string    `json:"tanggal" bson:"tanggal"`
	Description string    `json:"judul" bson:"judul"`
	Content     []Content `json:"content" bson:"content"`
}

type Tags struct {
	Tags []string `json:"tags" bson:"tags"`
}

type Category struct {
	Category []string `json:"category" bson:"category"`
}

type Comment struct {
	ID        int    `json:"id" bson:"id"`
	Username  string `json:"username" bson:"username"`
	Answer    string `json:"comment" bson:"comment"`
	Questions string `json:"questions" bson:"questions"`
	Tanggal   string `json:"tanggal" bson:"tanggal"`
}

type Share struct {
	Share []string `json:"share" bson:"share"`
}

type EventGlobal struct {
	ID          int    `json:"id" bson:"id"`
	Title       string `json:"title" bson:"title"`
	Description string `json:"description" bson:"description"`
	Tanggal     string `json:"tanggal" bson:"tanggal"`
	Image       string `json:"image" bson:"image"`
	Harga       int    `json:"harga" bson:"harga"`
}

type Event struct {
	ID          int    `json:"id" bson:"id"`
	Title       string `json:"title" bson:"title"`
	Description string `json:"description" bson:"description"`
	Tanggal     string `json:"tanggal" bson:"tanggal"`
	Image       string `json:"image" bson:"image"`
	Harga       int    `json:"harga" bson:"harga"`
	LinkYoutube string `json:"linkyoutube" bson:"linkyoutube"`
}

type About struct {
	ID          int    `json:"id" bson:"id"`
	Title       string `json:"title" bson:"title"`
	Description string `json:"description" bson:"description"`
	Image       string `json:"image" bson:"image"`
}

type Gallery struct {
	ID          int    `json:"id" bson:"id"`
	Title       string `json:"title" bson:"title"`
	Description string `json:"description" bson:"description"`
	Image       string `json:"image" bson:"image"`
}

type Contack struct {
	ID      int    `json:"id" bson:"id"`
	Name    string `json:"title" bson:"title"`
	Subject string `json:"description" bson:"description"`
	Message string `json:"image" bson:"image"`
	Email   string `json:"email" bson:"email"`
	Phone   string `json:"phone" bson:"phone"`
}

type Iklan struct {
	ID          int    `json:"id" bson:"id"`
	Title       string `json:"title" bson:"title"`
	Description string `json:"description" bson:"description"`
	Image       string `json:"image" bson:"image"`
}
