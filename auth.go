package gae_authen

import (
	"appengine"
	"appengine/datastore"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type User struct {
	Username   string
	SaltedHash []byte
}
type Authen struct {
	c appengine.Context
}

var (
	privateKey []byte
)

func NewAuthen(context appengine.Context) *Authen {
	privateKey = []byte("Ce7BTYq1Qm6wa2ZmHb6oNE8JPmj+BvxLFZUJprIByl0iS9OoxojJF8As33sXF5W5h5964suovxM9kWUp1IXIWw==")
	return &Authen{context}
}

func (authen *Authen) CreateUser(username string, password []byte) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword(password, 10)
	if err != nil {
		return "", err
	}
	authenKey := datastore.NewKey(authen.c, "authen", username, 0, nil)
	user := &User{username, hashedPassword}
	key, err := datastore.Put(authen.c, authenKey, user)
	return key.StringID(), err
}

func (authen *Authen) Login(username string, password []byte) (string, error) {
	authenKey := datastore.NewKey(authen.c, "authen", username, 0, nil)
	var u User
	err := datastore.Get(authen.c, authenKey, &u)
	if err != nil {
		return "", new(UserNotFound)
	}
	err = bcrypt.CompareHashAndPassword(u.SaltedHash, password)
	if err != nil {
		return "", new(WrongPasswordError)
	}
	token, err := getJwtForUser(u.Username)
	return token, nil
}

func getJwtForUser(username string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS512)
	token.Claims["username"] = username
	token.Claims["iss"] = "SttaCompWeb"
	token.Claims["iat"] = time.Now().Unix()
	token.Claims["exp"] = time.Now().Add(time.Minute * 30).Unix()
	return token.SignedString(privateKey)
}

func ParseToken(tokenString string) (*jwt.Token, error) {
	myToken, err := jwt.Parse(tokenString, func(tokenWithin *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := tokenWithin.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", tokenWithin.Header["alg"])
		}
		if tokenWithin.Method.Alg() != "HS512" {
			return nil, fmt.Errorf("Unexpected signing method string: %v", tokenWithin.Header["alg"])
		}
		exp, ok := tokenWithin.Claims["exp"].(float64)
		if !ok {
			return nil, fmt.Errorf("Token does not contain expiry claim")
		}
		if exp < float64(time.Now().Unix()) {
			return nil, fmt.Errorf("Token expired")
		}
		return []byte(""), nil
	})
	if err != nil {
		return nil, err
	}
	return myToken, err
}
