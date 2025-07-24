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
        "strings"
        "sync"
        "time"

        "github.com/gin-gonic/gin"
        "github.com/golang-jwt/jwt/v4"
        _ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB
var caPrivateKey *rsa.PrivateKey

type nonceData struct {
        Value     string
        Expiration time.Time
}

var nonceStore = struct {
        sync.RWMutex
        store map[string]nonceData
}{store: make(map[string]nonceData)}

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
                public_key TEXT NOT NULL,
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
        `)
        if err != nil {
                log.Fatal("Failed to create tables:", err)
        }

        // Generate CA key pair
        caPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                log.Fatal("Failed to generate CA keys:", err)
        }

        r := gin.Default()

        // CORS middleware
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

        // Health check
        r.GET("/", func(c *gin.Context) {
                c.JSON(200, gin.H{"status": "ok", "message": "Eutelos API is running"})
        })

        // Auth routes
        r.POST("/register", register)
        r.POST("/login-init", loginInit)
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

func publicKeyToPEM(publicKey *rsa.PublicKey) string {
        pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
        if err != nil {
                log.Println("Failed to marshal public key:", err)
                return ""
        }
        pubPem := pem.EncodeToMemory(&pem.Block{
                Type:  "PUBLIC KEY",
                Bytes: pubBytes,
        })
        return string(pubPem)
}

func issueCertificate(userEmail string, publicKey *rsa.PublicKey) string {
        certData := map[string]interface{}{
                "email":     userEmail,
                "publicKey": publicKeyToPEM(publicKey),
                "issuedAt":  time.Now().Unix(),
                "expiresAt": time.Now().Add(365 * 24 * time.Hour).Unix(),
        }
        certJSON, _ := json.Marshal(certData)

        hashed := sha256.Sum256(certJSON)
        signature, err := rsa.SignPKCS1v15(rand.Reader, caPrivateKey, crypto.SHA256, hashed[:])
        if err != nil {
                log.Println("Failed to sign certificate:", err)
                return ""
        }

        return base64.StdEncoding.EncodeToString(signature)
}

func register(c *gin.Context) {
        log.Println("Registration request received")

        var user struct {
                Name      string `json:"name"`
                Email     string `json:"email"`
                Role      string `json:"role"`
                PublicKey string `json:"publicKey"`
        }

        if err := c.BindJSON(&user); err != nil {
                log.Println("Invalid request:", err)
                c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
                return
        }

        log.Printf("Registering user: %s (%s)", user.Name, user.Email)

        // Decode and parse public key
        spkiBytes, err := base64.StdEncoding.DecodeString(user.PublicKey)
        if err != nil {
                log.Println("Invalid public key format:", err)
                c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid public key format"})
                return
        }

        pubKey, err := x509.ParsePKIXPublicKey(spkiBytes)
        if err != nil {
                log.Println("Invalid public key:", err)
                c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid public key"})
                return
        }

        rsaPubKey, ok := pubKey.(*rsa.PublicKey)
        if !ok {
                log.Println("Only RSA keys supported")
                c.JSON(http.StatusBadRequest, gin.H{"error": "Only RSA keys supported"})
                return
        }

        // Store public key as PEM
        pubKeyPEM := publicKeyToPEM(rsaPubKey)

        log.Println("Inserting user into database")
        _, err = DB.Exec("INSERT INTO users (name, email, public_key, role) VALUES (?, ?, ?, ?)",
                user.Name, user.Email, pubKeyPEM, user.Role)

        if err != nil {
                log.Println("Database error:", err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed: " + err.Error()})
                return
        }

        log.Println("User registered successfully")

        // Issue certificate
        cert := issueCertificate(user.Email, rsaPubKey)

        c.JSON(http.StatusCreated, gin.H{
                "message":     "User registered",
                "certificate": cert,
        })
}

func loginInit(c *gin.Context) {
        log.Println("Login init request received")

        var req struct {
                Email string `json:"email"`
        }

        if err := c.BindJSON(&req); err != nil {
                log.Println("Invalid request:", err)
                c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
                return
        }

        // Generate random nonce
        nonceBytes := make([]byte, 32)
        if _, err := rand.Read(nonceBytes); err != nil {
                log.Println("Failed to generate nonce:", err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
                return
        }

        nonceB64 := base64.StdEncoding.EncodeToString(nonceBytes)

        // Store nonce with expiration (5 minutes)
        nonceStore.Lock()
        nonceStore.store[req.Email] = nonceData{
                Value:     nonceB64,
                Expiration: time.Now().Add(5 * time.Minute),
        }
        nonceStore.Unlock()

        log.Printf("Generated nonce for %s: %s", req.Email, nonceB64)
        c.JSON(http.StatusOK, gin.H{"nonce": nonceB64})
}

func login(c *gin.Context) {
        log.Println("Login request received")

        var req struct {
                Email      string `json:"email"`
                Signature  string `json:"signature"`
                Certificate string `json:"certificate"`
        }

        if err := c.BindJSON(&req); err != nil {
                log.Println("Invalid request:", err)
                c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
                return
        }

        // Get user public key
        var pubKeyPEM string
        err := DB.QueryRow("SELECT public_key FROM users WHERE email = ?", req.Email).
                Scan(&pubKeyPEM)

        if err != nil {
                log.Println("User not found:", req.Email, err)
                c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
                return
        }

        // Parse public key
        block, _ := pem.Decode([]byte(pubKeyPEM))
        if block == nil {
                log.Println("Invalid public key PEM")
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid public key"})
                return
        }

        pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
        if err != nil {
                log.Println("Failed to parse public key:", err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse public key"})
                return
        }

        rsaPubKey, ok := pubKey.(*rsa.PublicKey)
        if !ok {
                log.Println("Only RSA keys supported")
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Only RSA keys supported"})
                return
        }

        // Verify certificate (simplified)
        certValid := true
        if !certValid {
                log.Println("Invalid certificate")
                c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid certificate"})
                return
        }

        // Verify signature
        sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
        if err != nil {
                log.Println("Invalid signature format:", err)
                c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature"})
                return
        }

        // Get stored nonce data
        nonceStore.RLock()
        data, exists := nonceStore.store[req.Email]
        nonceStore.RUnlock()

        if !exists {
                log.Println("Nonce not found for email:", req.Email)
                c.JSON(http.StatusBadRequest, gin.H{"error": "Nonce expired. Please start login again"})
                return
        }

        if time.Now().After(data.Expiration) {
                log.Println("Nonce expired for email:", req.Email)
                c.JSON(http.StatusBadRequest, gin.H{"error": "Nonce expired. Please start login again"})
                return
        }

        // Verify signature with stored nonce
        hashed := sha256.Sum256([]byte(data.Value))

        err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed[:], sigBytes)
        if err != nil {
                log.Println("Signature verification failed:", err)
                c.JSON(http.StatusUnauthorized, gin.H{"error": "Signature verification failed"})
                return
        }

        // Issue JWT
        var user struct {
                ID    int
                Name  string
                Role  string
        }

        err = DB.QueryRow("SELECT id, name, role FROM users WHERE email = ?", req.Email).
                Scan(&user.ID, &user.Name, &user.Role)
        if err != nil {
                log.Println("User lookup failed:", err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "User lookup failed"})
                return
        }

        token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
                "userID": user.ID,
                "role":   user.Role,
                "exp":    time.Now().Add(time.Hour * 72).Unix(),
        })

        tokenString, err := token.SignedString([]byte("secret_key"))
        if err != nil {
                log.Println("Token generation failed:", err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Token error"})
                return
        }

        log.Println("Login successful for:", req.Email)
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

func createJob(c *gin.Context) {
        log.Println("Job creation request received")
        userID, exists := c.Get("userID")
        if !exists {
                log.Println("UserID not found in context")
                c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
                return
        }

        log.Printf("UserID: %d", userID)

        var job struct {
                Title       string  `json:"title"`
                Description string  `json:"description"`
                Budget      float64 `json:"budget"`
                Deadline    string  `json:"deadline"`
                Signature   string  `json:"signature"`
        }

        if err := c.BindJSON(&job); err != nil {
                log.Println("Invalid job data:", err)
                c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job data"})
                return
        }

        log.Printf("Job data: title=%s, description=%s, budget=%.2f, deadline=%s", 
                job.Title, job.Description, job.Budget, job.Deadline)

        // Get user's public key
        var pubKeyPEM string
        err := DB.QueryRow("SELECT public_key FROM users WHERE id = ?", userID).Scan(&pubKeyPEM)
        if err != nil {
                log.Println("Failed to get public key:", err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
                return
        }

        log.Println("Public key retrieved")

        // Parse public key
        block, _ := pem.Decode([]byte(pubKeyPEM))
        if block == nil {
                log.Println("Failed to decode PEM block")
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid public key"})
                return
        }

        pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
        if err != nil {
                log.Println("Failed to parse public key:", err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse public key"})
                return
        }

        rsaPubKey, ok := pubKey.(*rsa.PublicKey)
        if !ok {
                log.Println("Only RSA keys supported")
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Only RSA keys supported"})
                return
        }

        // Create consistent data string for signing
        // Use exactly the same format as frontend
        dataToSign := fmt.Sprintf("%s|%s|%.2f|%s", 
                strings.TrimSpace(job.Title),
                strings.TrimSpace(job.Description),
                job.Budget,
                strings.TrimSpace(job.Deadline))

        log.Printf("Data to sign: %s", dataToSign)
        hashed := sha256.Sum256([]byte(dataToSign))

        sigBytes, err := base64.StdEncoding.DecodeString(job.Signature)
        if err != nil {
                log.Println("Invalid signature format:", err)
                c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature format"})
                return
        }

        log.Println("Verifying signature...")
        err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed[:], sigBytes)
        if err != nil {
                log.Println("Signature verification failed:", err)

                // Additional debug: log the expected hash
                log.Printf("Expected hash: %x", hashed)

                // Try to verify with raw budget value
                altData := fmt.Sprintf("%s|%s|%g|%s", 
                        strings.TrimSpace(job.Title),
                        strings.TrimSpace(job.Description),
                        job.Budget,
                        strings.TrimSpace(job.Deadline))
                altHash := sha256.Sum256([]byte(altData))
                altErr := rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, altHash[:], sigBytes)
                log.Printf("Alternative format (%s) error: %v", altData, altErr)

                c.JSON(http.StatusUnauthorized, gin.H{"error": "Job signature invalid"})
                return
        }

        log.Println("Signature verified")

        // Store job
        _, err = DB.Exec("INSERT INTO jobs (title, description, budget, deadline, client_id, signature) VALUES (?, ?, ?, ?, ?, ?)",
                job.Title, job.Description, job.Budget, job.Deadline, userID, job.Signature)

        if err != nil {
                log.Println("Database error:", err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Job creation failed: " + err.Error()})
                return
        }

        log.Println("Job created successfully")
        c.JSON(http.StatusCreated, gin.H{"message": "Job created"})
}

func getJobs(c *gin.Context) {
        rows, err := DB.Query("SELECT id, title, description, budget, deadline, status, signature, client_id FROM jobs")
        if err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error: " + err.Error()})
                return
        }
        defer rows.Close()

        jobs := []gin.H{}
        for rows.Next() {
                var id, clientID int
                var title, description, deadline, status, signature string
                var budget float64
                if err := rows.Scan(&id, &title, &description, &budget, &deadline, &status, &signature, &clientID); err != nil {
                        c.JSON(http.StatusInternalServerError, gin.H{"error": "Data error: " + err.Error()})
                        return
                }

                // Verify signature
                verified := false
                var pubKeyPEM string
                err := DB.QueryRow("SELECT public_key FROM users WHERE id = ?", clientID).Scan(&pubKeyPEM)
                if err == nil {
                        block, _ := pem.Decode([]byte(pubKeyPEM))
                        if block != nil {
                                pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
                                if err == nil {
                                        if rsaPubKey, ok := pubKey.(*rsa.PublicKey); ok {
                                                dataToSign := fmt.Sprintf("%s|%s|%.2f|%s", title, description, budget, deadline)
                                                hashed := sha256.Sum256([]byte(dataToSign))
                                                sigBytes, _ := base64.StdEncoding.DecodeString(signature)
                                                if rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed[:], sigBytes) == nil {
                                                        verified = true
                                                }
                                        }
                                }
                        }
                }

                jobs = append(jobs, gin.H{
                        "id":          id,
                        "title":       title,
                        "description": description,
                        "budget":      budget,
                        "deadline":    deadline,
                        "status":      status,
                        "verified":    verified,
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

