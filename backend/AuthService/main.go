package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type users struct {
	ID            uint   `gorm:"primarykey;size:16"`
	Username      string `gorm:"size:100"`
	Password_hash string
	Iat           time.Time
}

type TokenJWT struct {
	Username      string    `json:"username"`
	Password_hash string    `json:"password_hash"`
	Id            uint      `json:"id"`
	Iat           time.Time `json:"iat"`
	jwt.RegisteredClaims
}

func Registrate(c *gin.Context, secret_key string, db_url string) {
	db, err := gorm.Open(postgres.Open(db_url), &gorm.Config{})
	if err != nil {
		log.Fatal("error connecing to db")
	}

	username := c.PostForm("username")
	password := c.PostForm("password")

	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"err": "no username is given"})
		return
	}
	if password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"err": "no password is given"})
		return
	}

	registrationDate := time.Now()

	h := sha256.New()
	h.Write([]byte(username + password))
	password_hash := fmt.Sprintf("%x", h.Sum(nil))

	// create registration in db
	db.Create(&users{Username: username, Password_hash: password_hash, Iat: registrationDate})

	user := users{}
	db.Last(&user)
	id := user.ID
	// create jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":      username,
		"password_hash": password_hash,
		"id":            id,
		"iat":           registrationDate.AddDate(0, 1, 0),
	})

	jwtTOKEN, err := token.SignedString([]byte(secret_key))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"err": err})
	}

	c.JSON(http.StatusOK, gin.H{
		"TOKEN": jwtTOKEN,
	})
}

func Authentification(c *gin.Context, secret_key string, db_url string) {
	db, err := gorm.Open(postgres.Open(db_url), &gorm.Config{})
	if err != nil {
		log.Fatal("error connecing to db")
	}

	username := c.PostForm("username")
	password := c.PostForm("password")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"err": "no username is given"})
		return
	}
	if password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"err": "no password is given"})
		return
	}

	registrationDate := time.Now()

	h := sha256.New()
	h.Write([]byte(username + password))
	password_hash := fmt.Sprintf("%x", h.Sum(nil))

	//check if user is valid in db
	user := users{}
	result := db.Where(&users{Username: username, Password_hash: password_hash, ID: user.ID}).First(&user)

	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusBadRequest, gin.H{"err": "no such user"})
		return
	}
	id := user.ID

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":      username,
		"password_hash": password_hash,
		"id":            id,
		"iat":           registrationDate.AddDate(0, 1, 0),
	})

	jwtTOKEN, err := token.SignedString([]byte(secret_key))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"err": err})
	}

	c.JSON(http.StatusOK, gin.H{
		"TOKEN": jwtTOKEN,
	})
}

func CheckIsValidJWT(c *gin.Context, secret_key string, db_url string) {
	db, err := gorm.Open(postgres.Open(db_url), &gorm.Config{})
	if err != nil {
		log.Fatal("error connecing to db")
	}

	token := c.GetHeader("jwtTOKEN")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "no token was presented",
		})
		return
	}

	token_parsed, err := jwt.ParseWithClaims(token, &TokenJWT{}, func(token_args *jwt.Token) (interface{}, error) {
		if _, ok := token_args.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token_args.Header["alg"])
		}
		return []byte(secret_key), nil
	})

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"err": err})
	}

	if claims, ok := token_parsed.Claims.(*TokenJWT); ok {

		now := time.Now()
		//iat, err := time.Parse(time.RFC3339Nano, claims.Iat)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"err": "wrong time format", "errlog": err.Error()})
			return
		}
		if now.After(claims.Iat) {
			c.JSON(http.StatusBadRequest, gin.H{"err": "jwt expired"})
			return
		}

		username := claims.Username
		password_hash := claims.Password_hash
		id := claims.Id
		registrationDate := time.Now()

		//check is user is active in db
		user := users{}
		result := db.Where(&users{Username: username, Password_hash: password_hash, ID: id}).First(&user)
		log.Println(user.ID)

		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"err": "jwt is not valid; user is not definded"})
			return
		}

		// create jwt token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username":      username,
			"password_hash": password_hash,
			"id":            id,
			"iat":           registrationDate.AddDate(0, 1, 0),
		})

		new_token, err := token.SignedString([]byte(secret_key))

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"err": err})
		}

		c.JSON(http.StatusOK, gin.H{
			"new_updated_token": new_token,
		})

	} else {
		c.JSON(http.StatusBadRequest, gin.H{"err": "parsed badly"})
	}

}

func main() {
	// initialization
	err := godotenv.Load()

	if err != nil {
		log.Fatal("Error loading .env file")
	}

	secret_key := os.Getenv("SECRET_KEY")

	db_url := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=5432", os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_DB"))
	db, err := gorm.Open(postgres.Open(db_url), &gorm.Config{})
	if err != nil {
		log.Fatal("error connecing to db")
		return
	}
	db.AutoMigrate(&users{})
	var userss []users
	db.Find(&userss)
	for _, user := range userss {
		log.Println("delegin user", user.ID, user.Username, user.Password_hash, user.Iat)
		db.Delete(&user)
	}
	log.Println("end deleting")

	r := gin.Default()

	r.POST("/reg", func(c *gin.Context) {
		Registrate(c, secret_key, db_url)
	})

	r.POST("/auth", func(c *gin.Context) {
		Authentification(c, secret_key, db_url)
	})

	r.GET("/isvalidJWT", func(c *gin.Context) {
		CheckIsValidJWT(c, secret_key, db_url)
	})

	r.Run(":8080")
}
