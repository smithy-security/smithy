package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func init() {
	// Vulnerability 1: Hardcoded credentials
	var err error
	db, err = sql.Open("mysql", "root:password123@tcp(127.0.0.1:3306)/userdb")
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/search", searchHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/execute", executeHandler)

	log.Println("Server starting on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")

	// Vulnerability 2: SQL Injection
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Check if user exists
	if rows.Next() {
		fmt.Fprintf(w, "Welcome, %s!", username)
	} else {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	// Vulnerability 3: XSS (Cross-Site Scripting)
	query := r.URL.Query().Get("q")

	fmt.Fprintf(w, "<html><body>")
	fmt.Fprintf(w, "<h1>Search Results for: %s</h1>", query)
	fmt.Fprintf(w, "<p>No results found.</p>")
	fmt.Fprintf(w, "</body></html>")
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Vulnerability 4: Unrestricted File Upload
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error uploading file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create uploads directory if it doesn't exist
	os.MkdirAll("uploads", os.ModePerm)

	filename := filepath.Join("uploads", header.Filename)
	out, err := os.Create(filename)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	defer out.Close()

	// Copy file contents
	buffer := make([]byte, 1024)
	for {
		n, err := file.Read(buffer)
		if err != nil {
			break
		}
		out.Write(buffer[:n])
	}

	fmt.Fprintf(w, "File uploaded successfully: %s", header.Filename)
}

func executeHandler(w http.ResponseWriter, r *http.Request) {
	// Vulnerability 5: Command Injection
	command := r.URL.Query().Get("cmd")

	// Split the command and arguments
	parts := strings.Split(command, " ")

	cmd := exec.Command(parts[0], parts[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing command: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Command output: %s", string(output))
}
