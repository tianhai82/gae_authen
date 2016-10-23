package gae_authen

import (
	"fmt"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"

	"appengine"
	"appengine/datastore"
)

const AUTHEN = "_authen"

type User struct {
	Userid            string
	Username          string
	SaltedHash        []byte
	IsPasswordChanged bool
	Peep              []byte
}
type Authen struct {
	c          appengine.Context
	privateKey []byte
}

func NewAuthen(context appengine.Context, key []byte) *Authen {
	return &Authen{context, key}
}

func (authen *Authen) GetCurrentUserId(jwtCookie string) (string, error) {
	tok, err := authen.ParseToken(jwtCookie)
	if err != nil {
		return "", err
	}
	userId := tok.Claims["userid"].(string)
	return userId, nil
}

func (authen *Authen) CreateUser(userid string, username string, password []byte) (string, error) {
	userid = strings.ToLower(userid)
	hashedPassword, err := bcrypt.GenerateFromPassword(password, 10)
	if err != nil {
		return "", err
	}
	authenKey := datastore.NewKey(authen.c, AUTHEN, userid, 0, nil)
	user := &User{userid, username, hashedPassword, false, password}
	key, err := datastore.Put(authen.c, authenKey, user)
	return key.StringID(), err
}

func (authen *Authen) DeleteUsers(userids []string) error {
	var keys []*datastore.Key = make([]*datastore.Key, len(userids))
	for i, id := range userids {
		id = strings.ToLower(id)
		keys[i] = datastore.NewKey(authen.c, AUTHEN, id, 0, nil)
	}
	return datastore.DeleteMulti(authen.c, keys)
}

func (authen *Authen) ContainsUser(userid string) bool {
	key := datastore.NewKey(authen.c, AUTHEN, userid, 0, nil)
	var u User
	if err := datastore.Get(authen.c, key, &u); err != nil {
		return false
	}
	return true
}

func (authen *Authen) UpdateUser(userid string, username string) bool {
	key := datastore.NewKey(authen.c, AUTHEN, userid, 0, nil)
	var u User
	err := datastore.Get(authen.c, key, &u)
	if err != nil {
		return false
	}
	u.Username = username
	if _, err = datastore.Put(authen.c, key, &u); err != nil {
		return false
	}
	return true
}

func (authen *Authen) ChangePassword(userid string, newPw []byte) bool {
	key := datastore.NewKey(authen.c, AUTHEN, userid, 0, nil)
	var u User
	err := datastore.Get(authen.c, key, &u)
	if err != nil {
		return false
	}
	u.IsPasswordChanged = true
	u.Peep = []byte("")
	hashedPassword, err := bcrypt.GenerateFromPassword(newPw, 10)
	if err != nil {
		return false
	}
	u.SaltedHash = hashedPassword
	if _, err = datastore.Put(authen.c, key, &u); err != nil {
		return false
	}
	return true
}

func (authen *Authen) Login(userid string, password []byte, duration int) (string, error) {
	userid = strings.ToLower(userid)
	authenKey := datastore.NewKey(authen.c, AUTHEN, userid, 0, nil)
	var u User
	err := datastore.Get(authen.c, authenKey, &u)
	if err != nil {
		return "", new(UserNotFound)
	}
	err = bcrypt.CompareHashAndPassword(u.SaltedHash, password)
	if err != nil {
		return "", new(WrongPasswordError)
	}
	return authen.getJwtForUser(u.Userid, u.Username, duration, !u.IsPasswordChanged)
}

func (authen *Authen) getJwtForUser(userid string, username string, duration int, changePassword bool) (string, error) {
	userid = strings.ToLower(userid)
	token := jwt.New(jwt.SigningMethodHS512)
	token.Claims["userid"] = userid
	token.Claims["username"] = username
	token.Claims["cp"] = changePassword
	token.Claims["exp"] = time.Now().Add(time.Second * time.Duration(duration)).Unix()
	return token.SignedString(authen.privateKey)
}

func (authen *Authen) ParseToken(tokenString string) (*jwt.Token, error) {
	myToken, err := jwt.Parse(tokenString, func(tokenWithin *jwt.Token) (interface{}, error) {
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
		return authen.privateKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !myToken.Valid {
		return nil, fmt.Errorf("Token is invalid")
	}
	return myToken, err
}
