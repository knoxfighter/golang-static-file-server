package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Session struct {
	username string
	expiry   time.Time
}

var users map[string]string

var sessions map[string]Session

func (s *Session) isExpired() bool {
	return s.expiry.Before(time.Now())
}

func init() {
	users = make(map[string]string)
	sessions = make(map[string]Session)
}

const maxUploadSize = 2 * 1024 * 1024 * 1024 // 2 Gb
var uploadPath = "files/"

func main() {
	users[os.Getenv("username")] = os.Getenv("password")
	log.Printf("added user [%s] to ", os.Getenv("username"))

	http.HandleFunc("/upload", uploadFileHandler)
	http.HandleFunc("/login", loginHandler)

	fs := http.FileServer(http.Dir(uploadPath))
	http.Handle("/files/", http.StripPrefix("/files", fs))

	log.Print("Server started")
	log.Fatal(http.ListenAndServe(":80", nil))
}

func checkSession(w http.ResponseWriter, r *http.Request) (success bool) {
	success = false

	cookie, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionToken := cookie.Value

	session, ok := sessions[sessionToken]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if session.isExpired() {
		delete(sessions, sessionToken)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	return true
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		t, err := template.ParseFiles("login.gtpl")
		if err != nil {
			panic(err)
		}
		if t == nil {
			panic("Error parsing login template")
		}
		err = t.Execute(w, nil)
		if err != nil {
			panic(err)
		}
		return
	}

	err := r.ParseMultipartForm(10 * 1024) // 1kB
	if err != nil {
		log.Println("CANT_PARSE_FORM")
		renderError(w, "CANT_PARSE_FORM", http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	actualPassword, ok := users[username]

	if !ok || actualPassword != password {
		log.Println("wrong password")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token := uuid.NewString()
	expires := time.Now().Add(120 * time.Second)

	sessions[token] = Session{
		username: username,
		expiry:   expires,
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   token,
		Expires: expires,
	})

	http.Redirect(w, r, "/upload", http.StatusFound)
}

func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	if !checkSession(w, r) {
		return
	}

	if r.Method == "GET" {
		t, err := template.ParseFiles("upload.gtpl")
		if err != nil {
			panic(err)
		}
		if t == nil {
			panic("unable to parse upload template")
		}
		err = t.Execute(w, nil)
		if err != nil {
			panic(err)
		}
		return
	}
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		fmt.Printf("Could not parse multipart form: %v\n", err)
		renderError(w, "CANT_PARSE_FORM", http.StatusInternalServerError)
		return
	}

	// parse and validate file and post parameters
	file, fileHeader, err := r.FormFile("uploadFile")
	if err != nil {
		renderError(w, "INVALID_FILE", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Get and print out file size
	fileSize := fileHeader.Size
	fmt.Printf("File size (bytes): %v\n", fileSize)

	// validate file size
	if fileSize > maxUploadSize {
		renderError(w, "FILE_TOO_BIG", http.StatusBadRequest)
		return
	}

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		renderError(w, "INVALID_FILE", http.StatusBadRequest)
		return
	}

	// check file extension, we don't allow hash files
	fileExtension := filepath.Ext(fileHeader.Filename)

	if fileExtension == ".md5" || fileExtension == "sha1" || fileExtension == "sha256" || fileExtension == "sha512" {
		renderError(w, "INVALID_FILE_TYPE", http.StatusBadRequest)
		return
	}

	newPath := filepath.Join(uploadPath, fileHeader.Filename)

	// write file
	newFile, err := os.Create(newPath)
	if err != nil {
		renderError(w, "CANT_WRITE_FILE", http.StatusInternalServerError)
		return
	}
	defer newFile.Close() // idempotent, okay to call twice

	if _, err := newFile.Write(fileBytes); err != nil || newFile.Close() != nil {
		renderError(w, "CANT_WRITE_FILE", http.StatusInternalServerError)
		return
	}

	// create hash files for uploaded file
	md5Hash := md5.Sum(fileBytes)
	sha1Hash := sha1.Sum(fileBytes)
	sha256Hash := sha256.Sum256(fileBytes)
	sha512Hash := sha512.Sum512(fileBytes)

	md5HashStr := make([]byte, 32)
	sha1HashStr := make([]byte, 40)
	sha256HashStr := make([]byte, 64)
	sha512HashStr := make([]byte, 128)

	hex.Encode(md5HashStr, md5Hash[:])
	hex.Encode(sha1HashStr, sha1Hash[:])
	hex.Encode(sha256HashStr, sha256Hash[:])
	hex.Encode(sha512HashStr, sha512Hash[:])

	md5filePath := filepath.Join(uploadPath, fileHeader.Filename+".md5")
	err = os.WriteFile(md5filePath, md5HashStr, 0644)
	if err != nil {
		renderError(w, "CANT_WRITE_MD5", http.StatusInternalServerError)
		return
	}
	sha1filePath := filepath.Join(uploadPath, fileHeader.Filename+".sha1")
	err = os.WriteFile(sha1filePath, sha1HashStr, 0644)
	if err != nil {
		renderError(w, "CANT_WRITE_SHA1", http.StatusInternalServerError)
		return
	}
	sha256filePath := filepath.Join(uploadPath, fileHeader.Filename+".sha256")
	err = os.WriteFile(sha256filePath, sha256HashStr, 0644)
	if err != nil {
		renderError(w, "CANT_WRITE_SHA256", http.StatusInternalServerError)
		return
	}
	sha512filePath := filepath.Join(uploadPath, fileHeader.Filename+".sha512")
	err = os.WriteFile(sha512filePath, sha512HashStr, 0644)
	if err != nil {
		renderError(w, "CANT_WRITE_SHA512", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(fmt.Sprintf("SUCCESS - use <a href=\"https://static.knox.moe/files/%v\">/files/%v</a> to access the file", fileHeader.Filename, fileHeader.Filename)))
}

func renderError(w http.ResponseWriter, message string, statusCode int) {
	w.WriteHeader(statusCode)
	w.Write([]byte(message))
}
