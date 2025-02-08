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
	gorm.Model
	ID               uint      `gorm:"primarykey;size:16"`
	username         string    `gorm:"size:100"`
	hashed_password  string    `form:"hashed_password"`
	registrationDate time.Time `form:"registrationDate"`
}

func Registrate(c *gin.Context, secret_key string, db_url string) {
	db, err := gorm.Open(postgres.Open(db_url), &gorm.Config{})
	if err != nil {
		log.Fatal("error connecing to db")
	}
	username := c.PostForm("username")
	password := c.PostForm("password")
	fmt.Println(username)
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
	password_hash := h.Sum(nil)

	// create registration in db
	db.Create(&users{username: username, hashed_password: string(password_hash), registrationDate: registrationDate})

	user := users{}
	db.Last(&user)
	id := user.ID
	fmt.Println(id, user.username, user.registrationDate)
	// create jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":      username,
		"password_hash": password_hash,
		"id":            id,
		"iat":           registrationDate.AddDate(0, 1, 0),
	})
	//fmt.Println(username, string(password_hash), id, registrationDate.AddDate(0, 1, 0))

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
		fmt.Println(username)
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
	password_hash := h.Sum(nil)

	//check if user is valid in db
	user := users{}
	result := db.Where(&users{username: username, hashed_password: string(password_hash)}).First(&user)

	var tests []users
	test_err := db.Find(&tests)
	for _, test := range tests {
		fmt.Println(test.hashed_password, test.ID, test.username, errors.Is(test_err.Error, gorm.ErrRecordNotFound))
	}
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusBadRequest, gin.H{"err": "no such user"})
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
	token_parsed, err := jwt.Parse(token, func(token_args *jwt.Token) (interface{}, error) {
		if _, ok := token_args.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token_args.Header["alg"])
		}
		return []byte(secret_key), nil
	})

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"err": err})
	}

	if claims, ok := token_parsed.Claims.(jwt.MapClaims); ok {

		now := time.Now()
		if now.Before(claims["iat"].(time.Time)) {
			c.JSON(http.StatusBadRequest, gin.H{"err": "jwt expired"})
		}

		username := claims["username"]
		password_hash := claims["password_hash"]
		id := claims["id"]
		registrationDate := time.Now()

		//check is user is active in db

		user := users{}
		err := db.Where(&users{username: username.(string), hashed_password: password_hash.(string), ID: id.(uint)}).First(&user).Error

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"err": "jwt is not valid; user is not definded"})
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
		c.JSON(http.StatusBadRequest, gin.H{})
	}

}

func main() {
	// initialization
	err := godotenv.Load()

	if err != nil {
		log.Fatal("Error loading .env file")
	}

	secret_key := os.Getenv("SECRET_KEY")

	db_url := fmt.Sprintf("host=localhost user=%s password=%s dbname=%s port=5432", os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_DB"))
	db, err := gorm.Open(postgres.Open(db_url), &gorm.Config{})
	if err != nil {
		log.Fatal("error connecing to db")
	}
	db.AutoMigrate(&users{})
	db.Delete(&users{}).Commit()

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
