package app

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

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

		err := db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(&project).Error; err != nil {
				return err
			}

			// if user_id provided, validate and create link in users_project
			if req.UserID != "" {
				uid, err := uuid.Parse(req.UserID)
				if err != nil {
					return fmt.Errorf("invalid user_id: %w", err)
				}

				// ensure user exists
				var user User
				if err := tx.First(&user, "id = ?", uid).Error; err != nil {
					return err
				}

				rel := UsersProject{UserID: uid, ProjectID: project.ID}
				if err := tx.Create(&rel).Error; err != nil {
					return err
				}
			}
			return nil
		})

		if err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"project": project})
	}
}

type CreatePolicyRequest struct {
	Title               string `json:"title" binding:"required"`
	Description         string `json:"description" binding:"required"`
	ProblemStatement    string `json:"problem_statement" binding:"required"`
	TargetPopulation    string `json:"target_population" binding:"required"`
	Objectives          string `json:"objectives" binding:"required"` // newline-separated
	AlignmentVision2050 bool   `json:"alignment_vision_2050" binding:"required"`
	AlignmentNST        bool   `json:"alignment_nst" binding:"required"`
	ResponsibleMinistry string `json:"responsible_ministry"`
	PriorityLevel       string `json:"priority_level"`
}

// CreatePolicy creates a new policy and generates a policy code of the form POL-<YEAR>-<NNN>
func CreatePolicy(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CreatePolicyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Use a transaction to ensure atomic count and create
		var policy Policy
		err := db.Transaction(func(tx *gorm.DB) error {
			// generate code based on existing count
			var count int64
			if err := tx.Model(&Policy{}).Count(&count).Error; err != nil {
				return err
			}
			// increment for the new policy
			seq := count + 1
			code := fmt.Sprintf("POL-%d-%03d", time.Now().Year(), seq)

			policy = Policy{
				ID:                  uuid.New(),
				Title:               req.Title,
				Code:                code,
				Description:         req.Description,
				ProblemStatement:    req.ProblemStatement,
				TargetPopulation:    req.TargetPopulation,
				Objectives:          req.Objectives,
				AlignmentVision2050: req.AlignmentVision2050,
				AlignmentNST:        req.AlignmentNST,
				ResponsibleMinistry: req.ResponsibleMinistry,
				PriorityLevel:       req.PriorityLevel,
			}

			return tx.Create(&policy).Error
		})

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"policy": policy})
	}
}

// ListPolicies godoc
// @Summary List policies
// @Description Get list of policies filtered by title, code, priority_level, created_after, created_before
// @Tags policies
// @Accept json
// @Produce json
// @Param title query string false "Title contains"
// @Param code query string false "Policy code"
// @Param priority_level query string false "Priority level"
// @Param created_after query string false "Created after (RFC3339)"
// @Param created_before query string false "Created before (RFC3339)"
// @Success 200 {array} Policy
// @Failure 500 {object} map[string]string
// @Router /api/policies [get]
func ListPolicies(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		type PolicySummary struct {
			Title               string    `json:"title"`
			ResponsibleMinistry string    `json:"responsible_ministry"`
			PriorityLevel       string    `json:"priority_level"`
			CreatedAt           time.Time `json:"created_at"`
		}

		var summaries []PolicySummary
		if err := db.Model(&Policy{}).
			Select("title, responsible_ministry, priority_level, created_at").
			Order("created_at desc").
			Scan(&summaries).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"policies": summaries})
	}
}

// GetPolicy godoc
// @Summary Get policy by ID
// @Description Get detailed info for a policy by its ID
// @Tags policies
// @Accept json
// @Produce json
// @Param id path string true "Policy ID"
// @Success 200 {object} Policy
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/policies/{id} [get]
func GetPolicy(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		idStr := c.Param("id")
		if idStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing policy id"})
			return
		}

		uid, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy id"})
			return
		}

		var p Policy
		if err := db.First(&p, "id = ?", uid).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"policy": p})
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
		if err := db.Where("user_id = ?", user.ID).Find(&rels).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

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
