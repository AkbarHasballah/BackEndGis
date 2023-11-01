package BEGis

import (
	"net/http"
)

func RegisterLoginRoutes() {
	http.HandleFunc("/BEGis", LoginHandler)
}
