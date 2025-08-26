package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

// FORCE TEST
// FORCE TEST 3

// VULNERABLE: Direct string concatenation in SQL query
func getUserByID(userID string) (*User, error) {
	// This is vulnerable to SQL injection!
	query := "SELECT id, username, email FROM users WHERE id = " + userID

	row := db.QueryRow(query)
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// VULNERABLE: String formatting in SQL query
func loginUser(username, password string) bool {
	// This is vulnerable to SQL injection!
	query := fmt.Sprintf("SELECT id FROM users WHERE username = '%s' AND password = '%s'", username, password)

	var userID int
	err := db.QueryRow(query).Scan(&userID)
	return err == nil
}

// VULNERABLE: Dynamic WHERE clause construction
func searchUsers(searchTerm, orderBy string) ([]User, error) {
	var users []User

	// This is vulnerable to SQL injection!
	query := "SELECT id, username, email FROM users WHERE username LIKE '%" + searchTerm + "%' ORDER BY " + orderBy

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// VULNERABLE: HTTP handler with SQL injection
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")

	// This is vulnerable to SQL injection!
	query := "SELECT id, username, email, role FROM users WHERE id = " + userID

	row := db.QueryRow(query)
	var id int
	var username, email, role string

	err := row.Scan(&id, &username, &email, &role)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	fmt.Fprintf(w, "User: %s (%s) - Role: %s", username, email, role)
}

// VULNERABLE: Batch operations with string concatenation
func deleteMultipleUsers(userIDs []string) error {
	if len(userIDs) == 0 {
		return nil
	}

	// This is vulnerable to SQL injection!
	query := "DELETE FROM users WHERE id IN ("
	for i, id := range userIDs {
		if i > 0 {
			query += ", "
		}
		query += id // No quotes or sanitization!
	}
	query += ")"

	_, err := db.Exec(query)
	return err
}

// VULNERABLE: Complex query with multiple injection points
func getFilteredUsers(minAge, maxAge, city, profession string) ([]User, error) {
	var users []User

	// This is vulnerable to SQL injection in multiple places!
	query := "SELECT id, username, email FROM users WHERE 1=1"

	if minAge != "" {
		query += " AND age >= " + minAge
	}
	if maxAge != "" {
		query += " AND age <= " + maxAge
	}
	if city != "" {
		query += " AND city = '" + city + "'"
	}
	if profession != "" {
		query += " AND profession = '" + profession + "'"
	}

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// VULNERABLE: Raw SQL execution from user input
func executeCustomQuery(customSQL string) ([]map[string]interface{}, error) {
	// This is extremely dangerous - allows arbitrary SQL execution!
	rows, err := db.Query(customSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		result := make(map[string]interface{})
		for i, col := range columns {
			result[col] = values[i]
		}
		results = append(results, result)
	}

	return results, nil
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

func main() {
	var err error
	db, err = sql.Open("mysql", "user:password@tcp(localhost:3306)/testdb")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	http.HandleFunc("/user", getUserHandler)

	fmt.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
