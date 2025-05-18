package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

// User struct
type User struct {
	ID        int64     `json:"user_id"`
	Username  string    `json:"user_name"`
	CreatedAt time.Time `json:"created_at"`
	Role      string    `json:"role"`
}

// Database interaction functions
func initDatabase() *sql.DB {
	connStr := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable",
		"brajeshchandra", "brajesh", "gym_music_db")
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Log a message indicating that the users table is assumed to exist
	log.Println("Assuming the 'users' table already exists with the 'id', 'username', 'created_at', and 'role' columns.")

	return db
}

func getUserByUsername(db *sql.DB, username string) (*User, error) {
	row := db.QueryRow("SELECT id, user_name, created_at, role FROM gym_users WHERE user_name = $1", username)
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.CreatedAt, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func createUser(db *sql.DB, username string) (int64, error) {
	var id int64
	err := db.QueryRow("INSERT INTO gym_users (user_name, role) VALUES ($1, $2) RETURNING id", username, "user").Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// Session management functions
var loggedInUsers = make(map[string]int64) // Store session token to user ID

func generateSessionToken(username string) string {
	return fmt.Sprintf("local_session_%s_%d", username, time.Now().UnixNano())
}

func storeSession(token string, userID int64) {
	loggedInUsers[token] = userID
}

func getSessionUserID(token string) (int64, bool) {
	userID, ok := loggedInUsers[token]
	return userID, ok
}

func invalidateSession(token string) {
	delete(loggedInUsers, token)
}

// Authentication handler
func localLoginHandler(c *gin.Context, db *sql.DB) {
	var request struct {
		Username string `json:"username"`
	}

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	username := request.Username
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username cannot be empty"})
		return
	}

	user, err := getUserByUsername(db, username)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	var userID int64
	if user == nil {
		newID, err := createUser(db, username)
		if err != nil {
			log.Printf("Error creating user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}
		userID = newID
		fmt.Printf("New user created with username: %s, ID: %d\n", username, userID)
	} else {
		userID = user.ID
		fmt.Printf("User '%s' logged in with ID: %d\n", username, userID)
	}

	sessionToken := generateSessionToken(username)
	// todo: store in redis
	storeSession(sessionToken, userID)

	c.SetCookie("session_token", sessionToken, 3600, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Local login successful"})
}

// Logout handler
func localLogoutHandler(c *gin.Context) {
	sessionToken, err := c.Cookie("session_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	invalidateSession(sessionToken)
	c.SetCookie("session_token", "", -1, "/", "", false, true) // Expire the cookie
	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
	fmt.Printf("User with token '%s' logged out\n", sessionToken)
}

// Middleware for session authentication
func sessionAuthMiddleware(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionToken, err := c.Cookie("session_token")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
			return
		}

		userID, ok := getSessionUserID(sessionToken)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
			return
		}

		// Optionally, you could fetch the user from the database here
		// user, err := getUserByID(db, userID)
		// if err != nil || user == nil {
		// 	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user"})
		// 	return
		// }

		c.Set("user_id", userID)
		c.Next()
	}
}

func main() {
	db := initDatabase()
	defer db.Close()

	router := gin.Default()

	// Configure CORS middleware
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:3000"}                            // Allow requests from your frontend origin
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} // Specify allowed HTTP methods
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept"}                 // Specify allowed headers
	config.AllowCredentials = true                                                     // If you need to handle cookies or authorization headers
	router.Use(cors.New(config))

	router.POST("/auth/local/login", func(c *gin.Context) {
		localLoginHandler(c, db)
	})
	router.POST("/auth/local/logout", localLogoutHandler)

	router.GET("/protected", sessionAuthMiddleware(db), func(c *gin.Context) {
		userID := c.GetInt64("user_id")
		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Protected data for user ID: %d", userID)})
	})

	router.Run(":8080")
}
