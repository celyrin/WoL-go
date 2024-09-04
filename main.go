package main

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/natefinch/lumberjack.v2"
)

var db *sql.DB

var jwtKey = []byte("your_secret_key") // Secret key for JWT signing

//go:embed web/*
var webFiles embed.FS

var defaultMode string

func main() {
	// init log output to file
	log.SetOutput(&lumberjack.Logger{
		Filename:   "./wol.log",
		MaxSize:    10, // megabytes
		MaxBackups: 3,
		MaxAge:     28, // days
	})

	log.Printf("Starting Wake-on-LAN service")

	db = initDB()
	defer db.Close()

	if defaultMode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()

	// Setup login routes
	router.POST("/login", login)
	router.POST("/update-password", updatePassword)

	// Serving embedded files
	subFS, err := fs.Sub(webFiles, "web") // This creates a sub filesystem from the embedded files
	if err != nil {
		panic(err) // Handle error appropriately in production
	}
	router.StaticFS("/web", http.FS(subFS))

	// Setup API routes with JWT middleware
	router.POST("/macs", authorizeJWT(), addMacAddress)
	router.DELETE("/macs/:mac", authorizeJWT(), deleteMacAddress)
	router.GET("/macs", authorizeJWT(), listMacAddresses)
	router.POST("/macs/:mac/wake", authorizeJWT(), wakeMachine)

	// Redirect root to the static HTML file
	router.GET("/", func(c *gin.Context) {
		c.Redirect(302, "/web/index.html")
	})
	log.Printf("Wake-on-LAN service started on :9543")
	router.Run(":9543")
}

func initDB() *sql.DB {
	db, err := sql.Open("sqlite3", "wol.db")
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}

	createTables(db) // Ensure tables are created after confirming the DB connection
	insertDefaultAdmin(db)
	return db
}

func createTables(db *sql.DB) {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS mac_addresses (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL UNIQUE
        );`,
		`CREATE TABLE IF NOT EXISTS users (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            must_change_password INTEGER NOT NULL DEFAULT 1
        );`,
	}
	for _, stmt := range statements {
		_, err := db.Exec(stmt)
		if err != nil {
			log.Fatalf("Error creating table: %v", err)
		}
	}
}

func insertDefaultAdmin(db *sql.DB) {
	_, err := db.Exec("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", "admin", "PassW0rd")
	if err != nil {
		log.Fatalf("Error inserting default admin: %v", err)
	}
}

func authorizeJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		const BEARER_SCHEMA = "Bearer "
		authHeader := c.GetHeader("Authorization")
		tokenString := strings.TrimPrefix(authHeader, BEARER_SCHEMA)

		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "API token required"})
			log.Printf("API token required")
			return
		}

		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				log.Printf("unexpected signing method")
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtKey, nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("userID", claims["id"])
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid API token"})
			log.Printf("Invalid API token")
			return
		}
	}
}

func login(c *gin.Context) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		log.Printf("Invalid request")
		return
	}

	var user struct {
		ID                 int
		MustChangePassword int
	}
	err := db.QueryRow("SELECT id, must_change_password FROM users WHERE username = ? AND password = ?", credentials.Username, credentials.Password).Scan(&user.ID, &user.MustChangePassword)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Incorrect username or password")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password"})
		} else {
			log.Printf("Database error")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		Issuer:    "example.com",
		Subject:   strconv.Itoa(user.ID),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token"})
		log.Printf("Could not create token")
		return
	}
	log.Printf("User %s logged in", credentials.Username)

	c.JSON(http.StatusOK, gin.H{"token": tokenString, "user_id": user.ID, "must_change_password": user.MustChangePassword == 1})
}

func updatePassword(c *gin.Context) {
	var data struct {
		UserID      string `json:"user_id"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BindJSON(&data); err != nil {
		log.Printf("Invalid request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if len(data.NewPassword) < 8 || !regexp.MustCompile(`(?i)[a-z]`).MatchString(data.NewPassword) || !regexp.MustCompile(`[0-9]`).MatchString(data.NewPassword) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password does not meet complexity requirements"})
		log.Printf("Password does not meet complexity requirements: must be at least 8 characters long, contain at least one letter and one digit")
		return
	}

	_, err := db.Exec("UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?", data.NewPassword, data.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		log.Printf("Database error")
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": "Password updated successfully"})
}

func addMacAddress(c *gin.Context) {
	var mac struct {
		MAC string `json:"mac"`
	}
	if err := c.BindJSON(&mac); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		log.Printf("Invalid request")
		return
	}

	_, err := db.Exec("INSERT INTO mac_addresses (mac) VALUES (?)", mac.MAC)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		log.Printf("Database error: %v", err)
		return
	}
	c.Status(http.StatusOK)
}

func deleteMacAddress(c *gin.Context) {
	userID, _ := c.Get("userID")
	log.Println("User ID from JWT:", userID) // Logging for demonstration; remove in production

	mac := c.Param("mac")
	_, err := db.Exec("DELETE FROM mac_addresses WHERE mac = ?", mac)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		log.Printf("Database error: %v", err)
		return
	}
	c.Status(http.StatusOK)
}

func listMacAddresses(c *gin.Context) {
	rows, err := db.Query("SELECT mac FROM mac_addresses")
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		log.Printf("Database error: %v", err)
		return
	}
	defer rows.Close()

	var macs []string
	for rows.Next() {
		var mac string
		if err := rows.Scan(&mac); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			log.Printf("Database error: %v", err)
			return
		}
		macs = append(macs, mac)
	}
	c.JSON(http.StatusOK, macs)
}

func wakeMachine(c *gin.Context) {
	mac := c.Param("mac")
	err := sendMagicPacket(mac)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		log.Printf("Error sending magic packet: %v", err)
		return
	}
	c.Status(http.StatusOK)
}

func sendMagicPacket(macAddr string) error {
	target, err := net.ParseMAC(macAddr)
	if err != nil {
		return err
	}

	header := []byte{255, 255, 255, 255, 255, 255}
	var packet []byte
	packet = append(packet, header...)
	for i := 0; i < 16; i++ {
		packet = append(packet, target...)
	}

	conn, err := net.Dial("udp", "255.255.255.255:9")
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(packet)
	return err
}
