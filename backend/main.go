package main

import (
	"database/sql"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

func main() {
	// Initialize database
	var err error
	DB, err = sql.Open("sqlite3", "../database/eutelos.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	defer DB.Close()

	// Create tables
	_, err = DB.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT NOT NULL
	);
	
	CREATE TABLE IF NOT EXISTS jobs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		description TEXT NOT NULL,
		budget REAL NOT NULL,
		deadline TEXT NOT NULL,
		client_id INTEGER NOT NULL,
		status TEXT DEFAULT 'open'
	);
	`)
	if err != nil {
		log.Fatal("Failed to create tables:", err)
	}

	r := gin.Default()

	// Root route
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Welcome to Eutelos API"})
	})

	// CORS middleware
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Auth routes
	r.POST("/register", register)
	r.POST("/login", login)

	// Protected routes
	auth := r.Group("/")
	auth.Use(authMiddleware)
	{
		auth.POST("/jobs", createJob)
		auth.GET("/jobs", getJobs)
	}

	log.Println("Server running on :8080")
	log.Fatal(r.Run(":8080"))
}

func register(c *gin.Context) {
	var user struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}

	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password error"})
		return
	}

	_, err = DB.Exec("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
		user.Name, user.Email, string(hashedPassword), user.Role)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered"})
}

func login(c *gin.Context) {
	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var user struct {
		ID       int
		Name     string
		Password string
		Role     string
	}

	err := DB.QueryRow("SELECT id, name, password, role FROM users WHERE email = ?", creds.Email).
		Scan(&user.ID, &user.Name, &user.Password, &user.Role)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": user.ID,
		"role":   user.Role,
		"exp":    time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString([]byte("secret_key"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
		"user": gin.H{
			"id":    user.ID,
			"name":  user.Name,
			"email": creds.Email,
			"role":  user.Role,
		},
	})
}

func createJob(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var job struct {
		Title       string  `json:"title"`
		Description string  `json:"description"`
		Budget      float64 `json:"budget"`
		Deadline    string  `json:"deadline"`
	}

	if err := c.BindJSON(&job); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job data"})
		return
	}

	_, err := DB.Exec("INSERT INTO jobs (title, description, budget, deadline, client_id) VALUES (?, ?, ?, ?, ?)",
		job.Title, job.Description, job.Budget, job.Deadline, userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Job creation failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Job created"})
}

func getJobs(c *gin.Context) {
	rows, err := DB.Query("SELECT id, title, description, budget, deadline, status FROM jobs")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error: " + err.Error()})
		return
	}
	defer rows.Close()

	jobs := []gin.H{}
	for rows.Next() {
		var job struct {
			ID          int
			Title       string
			Description string
			Budget      float64
			Deadline    string
			Status      string
		}
		if err := rows.Scan(&job.ID, &job.Title, &job.Description, &job.Budget, &job.Deadline, &job.Status); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Data error: " + err.Error()})
			return
		}
		jobs = append(jobs, gin.H{
			"id":          job.ID,
			"title":       job.Title,
			"description": job.Description,
			"budget":      job.Budget,
			"deadline":    job.Deadline,
			"status":      job.Status,
		})
	}

	c.JSON(http.StatusOK, jobs)
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

	userID := int(claims["userID"].(float64))
	role := claims["role"].(string)

	c.Set("userID", userID)
	c.Set("role", role)
	c.Next()
}
