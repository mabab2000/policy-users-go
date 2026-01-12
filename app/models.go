package app

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID        uuid.UUID `gorm:"type:char(36);primaryKey" json:"id"`
	FullName  string    `gorm:"size:255;not null" json:"full_name"`
	Email     string    `gorm:"size:255;uniqueIndex;not null" json:"email"`
	Phone     string    `gorm:"size:64" json:"phone"`
	Password  string    `gorm:"size:255;not null" json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

type Project struct {
	ID           uuid.UUID `gorm:"type:char(36);primaryKey" json:"id"`
	ProjectName  string    `gorm:"size:255;not null" json:"project_name"`
	Organization string    `gorm:"size:255" json:"organization"`
	Description  string    `gorm:"type:text" json:"description"`
	Scorp        string    `gorm:"size:255" json:"scorp"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (p *Project) BeforeCreate(tx *gorm.DB) (err error) {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

type UsersProject struct {
	UserID    uuid.UUID `gorm:"type:char(36);primaryKey" json:"user_id"`
	ProjectID uuid.UUID `gorm:"type:char(36);primaryKey" json:"project_id"`
}
