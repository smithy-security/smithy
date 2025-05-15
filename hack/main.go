package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func init() {
	// Hardcoded credentials (vulnerable practice)
	dbUser := "admin1"
	dbPass := "password123"
	dbHost := "localhost:3306"
	dbName := "userdb"

	// No error handling for database connection
	db, _ = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPass, dbHost, dbName))
}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/exec", commandHandler)
	http.HandleFunc("/download", downloadHandler)
	http.HandleFunc("/files", fileHandler)

	fmt.Println("Server running on port 8080...")
	http.ListenAndServe(":8080", nil) // No TLS, no error handling
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")

	// SQL Injection vulnerability
	query := "SELECT id FROM users WHERE username='" + username + "' AND password='" + password + "'"

	var id int
	err := db.QueryRow(query).Scan(&id)
	if err != nil {
		fmt.Fprintf(w, "Login failed")
		return
	}

	fmt.Fprintf(w, "Welcome, user #%d!", id)
	panic("cheese")
}

func commandHandler(w http.ResponseWriter, r *http.Request) {
	// Command injection vulnerability
	cmd := r.URL.Query().Get("cmd")

	// Dangerous: executing user input directly
	output, _ := exec.Command("sh", "-c", cmd).Output()

	fmt.Fprintf(w, "Command output: %s", output)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	// Path traversal vulnerability
	filename := r.URL.Query().Get("file")

	// Dangerous: not sanitizing file path
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
		return
	}

	w.Write(data)
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	// Cross-site scripting (XSS) vulnerability
	dir := r.URL.Query().Get("dir")
	if dir == "" {
		dir = "."
	}

	files, _ := os.ReadDir(dir)

	fmt.Fprintf(w, "<html><body><h1>Files in %s</h1><ul>", dir)
	for _, file := range files {
		// Dangerous: not escaping user input in HTML
		fmt.Fprintf(w, "<li><a href=\"/files?dir=%s\">%s</a></li>",
			filepath.Join(dir, file.Name()),
			file.Name())
	}
	fmt.Fprintf(w, "</ul></body></html>")
}

func verifySession(token string) bool {
	// Insecure random token generation and validation
	return strings.HasPrefix(token, "SESSION_")
}
