# Golang simple authentication module for Google App Engine
## Installation
> go get github.com/tianhai82/gae_authen

## Usage
```Golang
import (
	"appengine"
	"github.com/tianhai82/gae_authen"
)
c := appengine.NewContext(r)

// Create new Authen instance
authen := NewAuthen(c, []byte("your 512 bits secret key"))

// create user
user, err := authen.CreateUser("testUser", []byte("P@ssw0rd"))

// try logging in
jwtTokenString, err = authen.Login("testUser", []byte("P@ssw0rd"))

// check whether user is still logged in (jwtTokenString is valid and not expired)
// will be called on every http request
// JWT token is implemented using https://github.com/dgrijalva/jwt-go
// to read claim values from the token, please read instruction at https://github.com/dgrijalva/jwt-go
jwtToken, err := authen.ParseToken(tokenString)

```