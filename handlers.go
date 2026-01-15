package main

import (
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var DBMutex sync.Mutex

type CreateUserRequest struct {
	FullName string `json:"full_name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Phone    string `json:"phone"`
	Password string `json:"password" binding:"required,min=6"`
}

func CreateUser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CreateUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
			return
		}

		user := User{
			ID:       uuid.New(),
			FullName: req.FullName,
			Email:    req.Email,
			Phone:    req.Phone,
			Password: string(hashed),
		}

		if err := db.Create(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"user": user})
	}
}

type CreateProjectRequest struct {
	ProjectName  string `json:"project_name" binding:"required"`
	Organization string `json:"organization"`
	Description  string `json:"description"`
	Scorp        string `json:"scorp"`
	UserID       string `json:"user_id"`
}

func CreateProject(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CreateProjectRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		project := Project{
			ID:           uuid.New(),
			ProjectName:  req.ProjectName,
			Organization: req.Organization,
			Description:  req.Description,
			Scorp:        req.Scorp,
		}

		if err := db.Create(&project).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// if user_id provided, validate and create link in users_project
		if req.UserID != "" {
			uid, err := uuid.Parse(req.UserID)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
				return
			}

			// ensure user exists
			var user User
			if err := db.First(&user, "id = ?", uid).Error; err != nil {
				if err == gorm.ErrRecordNotFound {
					c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			rel := UsersProject{UserID: uid, ProjectID: project.ID}
			if err := db.Create(&rel).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}

		c.JSON(http.StatusCreated, gin.H{"project": project})
	}
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func Login(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var user User
		if err := db.First(&user, "email = ?", req.Email).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		secret := os.Getenv("JWT_SECRET")
		if secret == "" {
			secret = "secret"
		}

		claims := jwt.RegisteredClaims{
			Subject:   user.ID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString([]byte(secret))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create token"})
			return
		}

		var rels []UsersProject
		DBMutex.Lock()
		if err := db.Where("user_id = ?", user.ID).Find(&rels).Error; err != nil {
			DBMutex.Unlock()
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		DBMutex.Unlock()

		projectIDs := make([]uuid.UUID, 0, len(rels))
		for _, r := range rels {
			projectIDs = append(projectIDs, r.ProjectID)
		}

		c.JSON(http.StatusOK, gin.H{"token": "Bearer " + signed, "user_id": user.ID, "project_ids": projectIDs})
	}
}

func GetUser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		idStr := c.Param("id")
		if idStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing user id"})
			return
		}

		uid, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
			return
		}

		var user User
		if err := db.First(&user, "id = ?", uid).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var rels []UsersProject
		if err := db.Where("user_id = ?", uid).Find(&rels).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		projectsResp := make([]gin.H, 0, len(rels))
		if len(rels) > 0 {
			ids := make([]uuid.UUID, 0, len(rels))
			for _, r := range rels {
				ids = append(ids, r.ProjectID)
			}

			var projects []Project
			if err := db.Where("id IN ?", ids).Find(&projects).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			for _, p := range projects {
				projectsResp = append(projectsResp, gin.H{"project_id": p.ID, "project_name": p.ProjectName, "organization": p.Organization})
			}
		}

		c.JSON(http.StatusOK, gin.H{"user": user, "projects": projectsResp})
	}
}

func GetUserProjects(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		idStr := c.Param("id")
		if idStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing user id"})
			return
		}

		uid, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
			return
		}

		var rels []UsersProject
		if err := db.Where("user_id = ?", uid).Find(&rels).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if len(rels) == 0 {
			c.JSON(http.StatusOK, gin.H{"projects": []Project{}})
			return
		}

		ids := make([]uuid.UUID, 0, len(rels))
		for _, r := range rels {
			ids = append(ids, r.ProjectID)
		}

		var projects []Project
		if err := db.Where("id IN ?", ids).Find(&projects).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"projects": projects})
	}
}
