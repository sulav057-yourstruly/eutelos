package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	_ "github.com/mattn/go-sqlite3"
)

var (
	DB           *sql.DB
	caPrivateKey *rsa.PrivateKey
)

type nonceData struct {
	Value     string
	Expiration time.Time
}

var nonceStore = struct {
	sync.RWMutex
	store map[string]nonceData
}{store: make(map[string]nonceData)}

func main() {
	initDatabase()
	defer DB.Close()

	initCA()

	router := setupRouter()
	log.Println("Server running on :8080")
	log.Fatal(router.Run(":8080"))
}

func initDatabase() {
	var err error
	os.MkdirAll("./database", 0755)
	DB, err = sql.Open("sqlite3", "./database/eutelos.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	_, err = DB.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT UNIQUE NOT NULL,
		public_key TEXT NOT NULL,
		private_key TEXT NOT NULL,
		role TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS jobs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		description TEXT NOT NULL,
		budget REAL NOT NULL,
		deadline TEXT NOT NULL,
		client_id INTEGER NOT NULL,
		status TEXT DEFAULT 'open',
		signature TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS admins (
		user_id INTEGER PRIMARY KEY,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`)
	if err != nil {
		log.Fatal("Failed to create tables:", err)
	}
}

func initCA() {
	var err error
	caPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("Failed to generate CA keys:", err)
	}
}

func setupRouter() *gin.Engine {
	r := gin.Default()

	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Public routes
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.POST("/register", register)
	r.POST("/login-init", loginInit)
	r.POST("/login", login)

	// Authenticated routes
	auth := r.Group("/")
	auth.Use(authMiddleware)
	{
		auth.POST("/jobs", createJob)
		auth.GET("/jobs", getJobs)
		auth.GET("/admin/dashboard", adminDashboard)
	}

	// Admin routes
	admin := auth.Group("/admin")
	admin.Use(adminMiddleware)
	{
		admin.DELETE("/jobs/:id", deleteJob)
		admin.DELETE("/users/:id", deleteUser)
		admin.POST("/make-admin/:id", makeAdmin)
	}

	return r
}

func register(c *gin.Context) {
	var user struct {
		Name       string `json:"name"`
		Email      string `json:"email"`
		Role       string `json:"role"`
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	}

	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	spkiBytes, err := base64.StdEncoding.DecodeString(user.PublicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid public key format"})
		return
	}

	pubKey, err := x509.ParsePKIXPublicKey(spkiBytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid public key"})
		return
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only RSA keys supported"})
		return
	}

	pubKeyPEM := publicKeyToPEM(rsaPubKey)

	result, err := DB.Exec(
		"INSERT INTO users (name, email, public_key, private_key, role) VALUES (?, ?, ?, ?, ?)",
		user.Name, user.Email, pubKeyPEM, user.PrivateKey, user.Role,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed"})
		return
	}

	userID, _ := result.LastInsertId()
	var userCount int
	DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if userCount == 1 {
		DB.Exec("INSERT INTO admins (user_id) VALUES (?)", userID)
	}

	cert := issueCertificate(user.Email, rsaPubKey)
	c.JSON(http.StatusCreated, gin.H{
		"message":     "User registered",
		"certificate": cert,
		"userId":      userID,
	})
}

func loginInit(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	nonceB64 := base64.StdEncoding.EncodeToString(nonceBytes)
	nonceStore.Lock()
	nonceStore.store[req.Email] = nonceData{
		Value:     nonceB64,
		Expiration: time.Now().Add(5 * time.Minute),
	}
	nonceStore.Unlock()

	c.JSON(http.StatusOK, gin.H{"nonce": nonceB64})
}

func login(c *gin.Context) {
	var req struct {
		Email      string `json:"email"`
		Signature  string `json:"signature"`
		Certificate string `json:"certificate"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var user struct {
		ID         int
		Name       string
		Role       string
		PublicKey  string
		PrivateKey string
	}
	err := DB.QueryRow(`
		SELECT id, name, role, public_key, private_key 
		FROM users 
		WHERE email = ?`, req.Email).
		Scan(&user.ID, &user.Name, &user.Role, &user.PublicKey, &user.PrivateKey)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	nonceStore.RLock()
	data, exists := nonceStore.store[req.Email]
	nonceStore.RUnlock()

	if !exists || time.Now().After(data.Expiration) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired nonce"})
		return
	}

	block, _ := pem.Decode([]byte(user.PublicKey))
	if block == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid public key format"})
		return
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse public key"})
		return
	}

	rsaPubKey := pubKey.(*rsa.PublicKey)
	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature format"})
		return
	}

	hashed := sha256.Sum256([]byte(data.Value))
	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed[:], sigBytes)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Signature verification failed"})
		return
	}

	var isAdmin bool
	DB.QueryRow("SELECT 1 FROM admins WHERE user_id = ?", user.ID).Scan(&isAdmin)
	if isAdmin {
		user.Role = "admin"
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": user.ID,
		"role":   user.Role,
		"exp":    time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString([]byte("secret_key"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
		"user": gin.H{
			"id":    user.ID,
			"name":  user.Name,
			"email": req.Email,
			"role":  user.Role,
		},
	})
}

func authMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret_key"), nil
	})

	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	c.Set("userID", int(claims["userID"].(float64)))
	c.Set("role", claims["role"].(string))
	c.Next()
}

func adminMiddleware(c *gin.Context) {
	userID, _ := c.Get("userID")
	var isAdmin bool
	err := DB.QueryRow("SELECT 1 FROM admins WHERE user_id = ?", userID).Scan(&isAdmin)
	if err != nil || !isAdmin {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}
	c.Next()
}

func publicKeyToPEM(publicKey *rsa.PublicKey) string {
	pubBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY", 
		Bytes: pubBytes,
	}))
}

func issueCertificate(email string, pubKey *rsa.PublicKey) string {
	certData := map[string]interface{}{
		"email":     email,
		"publicKey": publicKeyToPEM(pubKey),
		"issuedAt":  time.Now().Unix(),
		"expiresAt": time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	certJSON, _ := json.Marshal(certData)
	hashed := sha256.Sum256(certJSON)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, caPrivateKey, crypto.SHA256, hashed[:])
	return base64.StdEncoding.EncodeToString(signature)
}

func createJob(c *gin.Context) {
	userID, _ := c.Get("userID")
	var job struct {
		Title       string  `json:"title"`
		Description string  `json:"description"`
		Budget      float64 `json:"budget"`
		Deadline    string  `json:"deadline"`
		Signature   string  `json:"signature"`
	}

	if err := c.BindJSON(&job); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job data"})
		return
	}

	var pubKeyPEM string
	DB.QueryRow("SELECT public_key FROM users WHERE id = ?", userID).Scan(&pubKeyPEM)

	block, _ := pem.Decode([]byte(pubKeyPEM))
	pubKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
	rsaPubKey := pubKey.(*rsa.PublicKey)

	dataToSign := fmt.Sprintf("%s|%s|%.2f|%s|%d", 
		job.Title, job.Description, job.Budget, job.Deadline, userID)
	hashed := sha256.Sum256([]byte(dataToSign))

	sigBytes, _ := base64.StdEncoding.DecodeString(job.Signature)
	if err := rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed[:], sigBytes); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid job signature"})
		return
	}

	_, err := DB.Exec(
		"INSERT INTO jobs (title, description, budget, deadline, client_id, signature) VALUES (?, ?, ?, ?, ?, ?)",
		job.Title, job.Description, job.Budget, job.Deadline, userID, job.Signature,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Job creation failed"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Job created"})
}

func getJobs(c *gin.Context) {
	rows, err := DB.Query(`
		SELECT j.id, j.title, j.description, j.budget, j.deadline, 
			   j.status, j.signature, j.client_id, u.name as client_name
		FROM jobs j
		JOIN users u ON j.client_id = u.id
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	defer rows.Close()

	var jobs []gin.H
	for rows.Next() {
		var id, clientID int
		var title, description, deadline, status, signature, clientName string
		var budget float64
		rows.Scan(&id, &title, &description, &budget, &deadline, &status, &signature, &clientID, &clientName)

		jobs = append(jobs, gin.H{
			"id":          id,
			"title":       title,
			"description": description,
			"budget":      budget,
			"deadline":    deadline,
			"status":      status,
			"clientId":    clientID,
			"clientName":  clientName,
		})
	}

	c.JSON(http.StatusOK, jobs)
}

func adminDashboard(c *gin.Context) {
	rows, err := DB.Query("SELECT id, name, email, role FROM users")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	defer rows.Close()

	var users []gin.H
	for rows.Next() {
		var id int
		var name, email, role string
		rows.Scan(&id, &name, &email, &role)
		users = append(users, gin.H{
			"id":    id,
			"name":  name,
			"email": email,
			"role":  role,
		})
	}

	rows, err = DB.Query("SELECT id, title, budget, status, client_id FROM jobs")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	defer rows.Close()

	var jobs []gin.H
	for rows.Next() {
		var id, clientID int
		var title, status string
		var budget float64
		rows.Scan(&id, &title, &budget, &status, &clientID)
		jobs = append(jobs, gin.H{
			"id":       id,
			"title":    title,
			"budget":   budget,
			"status":   status,
			"clientId": clientID,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"jobs":  jobs,
	})
}

func deleteJob(c *gin.Context) {
	jobID := c.Param("id")
	_, err := DB.Exec("DELETE FROM jobs WHERE id = ?", jobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete job"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "Job deleted"})
}

func deleteUser(c *gin.Context) {
	userID := c.Param("id")
	_, err := DB.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "User deleted"})
}

func makeAdmin(c *gin.Context) {
	userID := c.Param("id")
	_, err := DB.Exec("INSERT OR IGNORE INTO admins (user_id) VALUES (?)", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to make admin"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "User is now admin"})
}
