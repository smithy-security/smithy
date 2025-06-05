package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

// 1. SQL Injection Vulnerability (CWE-89)
func getUserByID(db *sql.DB, userID string) (*User, error) {
	// VULNERABLE: Direct string concatenation allows SQL injection
	query := "SELECT id, username, email FROM users WHERE id = " + userID

	row := db.QueryRow(query)
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email)
	return &user, err
}

// 2. Command Injection Vulnerability (CWE-78)
func pingHost(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	// VULNERABLE: Direct command execution with user input
	cmd := exec.Command("ping", "-c", "1", host)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Ping failed", http.StatusInternalServerError)
		return
	}

	w.Write(output)
}

// 3. Path Traversal Vulnerability (CWE-22)
func serveFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	// VULNERABLE: No validation allows directory traversal
	content, err := ioutil.ReadFile("/var/www/files/" + filename)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	w.Write(content)
}

// 4. Weak Cryptographic Hash (CWE-327)
func hashPassword(password string) string {
	// VULNERABLE: MD5 is cryptographically broken
	hash := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// 5. Hardcoded Credentials (CWE-798)
func connectToDatabase() (*sql.DB, error) {
	// VULNERABLE: Hardcoded database credentials
	db, err := sql.Open("mysql", "admin:password123@tcp(localhost:3306)/mydb")
	return db, err
}

// 6. Insufficient Input Validation (CWE-20)
func transferMoney(w http.ResponseWriter, r *http.Request) {
	amountStr := r.FormValue("amount")

	// VULNERABLE: No validation on amount
	amount, _ := strconv.ParseFloat(amountStr, 64)

	// This could allow negative amounts or extremely large values
	fmt.Fprintf(w, "Transferring $%.2f", amount)
}

// 7. Cross-Site Scripting (XSS) - Reflected (CWE-79)
func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")

	// VULNERABLE: Direct output of user input without escaping
	fmt.Fprintf(w, "<h1>Search Results for: %s</h1>", query)
	fmt.Fprintf(w, "<p>No results found for '%s'</p>", query)
}

// 8. Insecure Random Number Generation (CWE-338)
func generateSessionToken() string {
	// VULNERABLE: Using math/rand instead of crypto/rand
	// Note: This example assumes math/rand is used somewhere
	return "session_" + strconv.Itoa(12345) // Predictable token
}

// 9. Information Disclosure (CWE-200)
func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// VULNERABLE: Detailed error messages reveal system information
	if username == "" {
		http.Error(w, "Username cannot be empty. Database connection: mysql://admin@localhost:3306/users", http.StatusBadRequest)
		return
	}

	if len(password) < 8 {
		http.Error(w, "Password must be at least 8 characters. Current length: "+strconv.Itoa(len(password)), http.StatusBadRequest)
		return
	}
}

// 10. Race Condition (CWE-362)
var counter int

func incrementCounter(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: Race condition on shared variable
	counter++
	fmt.Fprintf(w, "Counter: %d", counter)
}

// 11. Improper Certificate Validation (CWE-295)
func makeInsecureHTTPSRequest(url string) error {
	// VULNERABLE: This would disable certificate validation
	// tr := &http.Transport{
	//     TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	// }
	// client := &http.Client{Transport: tr}

	// For demo purposes, just showing the concept
	fmt.Println("Making request to:", url)
	return nil
}

// 12. Buffer Overflow (Slice Bounds) (CWE-120)
func processData(data []byte, index int) byte {
	// VULNERABLE: No bounds checking
	return data[index] // Could panic with index out of range
}

// 13. Denial of Service - Resource Exhaustion (CWE-400)
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: No size limit on file uploads
	file, _, err := r.FormFile("upload")
	if err != nil {
		http.Error(w, "Upload failed", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// This could consume all available memory
	data, _ := ioutil.ReadAll(file)
	fmt.Fprintf(w, "Uploaded %d bytes", len(data))
}

// 14. Insecure Direct Object Reference (CWE-639)
func getUserProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")

	// VULNERABLE: No authorization check
	// Any user can access any other user's profile
	fmt.Fprintf(w, "Profile for user ID: %s", userID)
}

// 15. Log Injection (CWE-117)
func logUserAction(username, action string) {
	// VULNERABLE: User input directly in logs without sanitization
	log.Printf("User %s performed action: %s", username, action)
	// An attacker could inject newlines and fake log entries
}

// Supporting structures
type User struct {
	ID       int
	Username string
	Email    string
}

// Example of how these vulnerabilities could be exploited:
/*
1. SQL Injection: ?userID=1 OR 1=1 --
2. Command Injection: ?host=localhost; rm -rf /
3. Path Traversal: ?file=../../../etc/passwd
4. XSS: ?q=<script>alert('XSS')</script>
5. DoS: Upload extremely large files
6. Log Injection: username="admin\nFAKE LOG ENTRY"
*/

func main() {
	// This is just example code - don't run in production!
	fmt.Println("These are examples of vulnerable code patterns.")
	fmt.Println("Each function above demonstrates a different security vulnerability.")
	fmt.Println("Use static analysis tools like SonarQube to detect these issues!")
}
