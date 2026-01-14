package main

import (
	"net/http"
	"net/url"
	"os"
	"time"

	"database/sql"
	"policy-users-go/app"

	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	// load .env if present
	_ = godotenv.Load()

	// initialize DB: require DATABASE_URL (Postgres)
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		panic("DATABASE_URL environment variable is required; see .env")
	}

	// ensure we use simple protocol to avoid prepared statement name conflicts
	// add query param prefer_simple_protocol=true if not already present
	if u, err := url.Parse(dbURL); err == nil {
		q := u.Query()
		if q.Get("prefer_simple_protocol") == "" && q.Get("preferSimpleProtocol") == "" {
			q.Set("prefer_simple_protocol", "true")
			q.Set("preferSimpleProtocol", "true")
			u.RawQuery = q.Encode()
			dbURL = u.String()
		}
	}

	// Open sql.DB using lib/pq to avoid pgx prepared-statement cache issues with poolers
	var db *gorm.DB
	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		panic(err)
	}
	db, err = gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	// Migrate tables: users, projects, users_project
	if err := db.AutoMigrate(&app.User{}, &app.Project{}, &app.UsersProject{}); err != nil {
		println("migration warning:", err.Error())
	}

	r := gin.Default()

	// enable CORS for all origins
	r.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// API routes
	api := r.Group("/api")
	{
		api.POST("/users", app.CreateUser(db))
		api.POST("/projects", app.CreateProject(db))
		api.POST("/login", app.Login(db))
		api.GET("/users/:id", app.RequireAuthMatchingParam(), app.GetUser(db))
		api.GET("/users/:id/projects", app.RequireAuthMatchingParam(), app.GetUserProjects(db))
	}

	// Serve OpenAPI YAML and Swagger UI
	r.GET("/swagger.yaml", func(c *gin.Context) {
		c.File("docs/openapi.yaml")
	})
	r.GET("/swagger", func(c *gin.Context) {
		c.File("templates/swagger.html")
	})

	// simple health
	r.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })

	// start server, allow PORT override and fallback if port is busy
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	if err := r.Run(addr); err != nil {
		// try fallback port
		fallback := ":8081"
		_ = os.Setenv("PORT", "8081")
		if err2 := r.Run(fallback); err2 != nil {
			panic(err2)
		}
	}
}
