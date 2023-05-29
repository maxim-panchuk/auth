package main

import (
	"auth/domain"
	"auth/entity"
	"auth/migrations"
	"auth/repository/userRepository"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v4"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"net/http"
	"time"
)

var databaseFetchError = errors.New("database fetch error")
var DatabaseFetchError = echo.NewHTTPError(http.StatusInternalServerError, "Database fetch error")

var refreshTokenFromDbNotTheSame = errors.New("refresh token from db is not the same as in request")
var RefreshTokenFromDbNotTheSame = echo.NewHTTPError(http.StatusUnauthorized, "Refresh token from db is not the same as in request")

var accessTokenExpired = errors.New("access token expired")
var AccessTokenExpired = echo.NewHTTPError(http.StatusUnauthorized, "Access token expired")

var accessTokenParsingError = errors.New("access token parsing error")
var AccessTokenParsingError = echo.NewHTTPError(http.StatusUnauthorized, "Access token parsing error")

var refreshTokenParsingError = errors.New("refresh token parsing error")
var RefreshTokenParsingError = echo.NewHTTPError(http.StatusUnauthorized, "Refresh token parsing error")

/*
	Авторизация или регистрация -> /auth [РЕГИСТРАЦИЯ]
	type Credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}

	Response Body:
		ошибка типа: AccessTokenExpired, accessTokenParsingError, проверить по
		сообщениям: access token parsing error  401,
					access token expired,
					missing or malformed jwt

		Значит нужно отдать по тому же урлу refresh_token
				ПРАВИЛО: Если был отдан refresh_token, значит респонсом вернется новый рефреш токен

	Response Headers
	Если был передан "X-Access-Token", - сохранить в памяти и совать во все запросы
	Если быд передан "X-Refresh-Token", - нужно сохранить и присылвать в этом же заголовке только когда вернулась



	Если был передан в прокси refresh_token - и что то пошло не так или это пользователя такого нет
							или токен был скомпрометирован и его неудалось спарсить
							или его время жизни истекло
							или не совпадает с сохраннеым в базе
							или не удалось извлечь пользователя по токену -
			REDIRECT TO /login


	В ОБЩИХ СЛОВАХ:
		X-Access-Token - передавать всегда и везде, можно не передавать только если пользователь сам хочет
			зайти на авторизацию
		X-Refresh-Token - Передавать только когда об этом попросит прокси (такие случае описаны выше)

		Если на прокси был отправлен X-Refresh-Token - значит он вернется в том же заголовке и его нужно обновить


	ПРОКСИ отправит на бэк заголовки:
		Username, Role

*/

var client *resty.Client

func main() {

	client = resty.New()

	db := initDb()
	err := migrations.Migrate(db)
	if err != nil {
		panic(err)
	}

	userRepo := userRepository.NewUserRepository(db)

	e := echo.New()

	e.Use(echojwt.WithConfig(echojwt.Config{
		Skipper: func(c echo.Context) bool {
			if c.Request().URL.Path == "/login" {
				return true
			}
			if c.Request().URL.Path == "/register" {
				return true
			}
			return false
		},
		BeforeFunc: func(c echo.Context) {

		},
		SuccessHandler: func(c echo.Context) {
			handle(c)
		},
		ErrorHandler: func(c echo.Context, err error) error {
			if errors.Is(err, databaseFetchError) {
				// INTERNAL SERVER ERROR
				return DatabaseFetchError
			}

			if errors.Is(err, refreshTokenFromDbNotTheSame) {
				// TODO redirect to login page
				return RefreshTokenFromDbNotTheSame
			}

			if errors.Is(err, refreshTokenParsingError) {
				// TODO redirect to login page
				return RefreshTokenParsingError
			}

			if errors.Is(err, accessTokenExpired) {
				// it is expected to get refreshToken from frontend
				return AccessTokenExpired
			}

			if errors.Is(err, accessTokenParsingError) {
				// TODO redirect to login page
				return AccessTokenParsingError
			}

			// LOGIN PAGE REDIRECTION
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		},
		TokenLookup:            "header:X-Access-Token",
		ContinueOnIgnoredError: false,

		ParseTokenFunc: func(c echo.Context, auth string) (interface{}, error) {

			refreshTokenString := c.Request().Header.Get("X-Refresh-Token")
			if refreshTokenString != "" {

				refreshToken, err := jwt.ParseWithClaims(refreshTokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
					return []byte("secret"), nil
				})
				if err != nil {
					log.Println("parse refreshToken error: ", err)
					return nil, refreshTokenParsingError
				}

				// TODO check if user exists [done]
				username := refreshToken.Claims.(jwt.MapClaims)["username"].(string)
				role := refreshToken.Claims.(jwt.MapClaims)["role"].(string)
				refreshTokenFromDb, err := userRepo.GetRefreshTokenByUsername(username)
				if err != nil {
					log.Println("get refreshToken from db error: ", err)
					return nil, databaseFetchError
				}

				if refreshTokenString != refreshTokenFromDb {
					return nil, refreshTokenFromDbNotTheSame
				}

				// TODO update refresh token [done]
				newRefreshToken, err := generateJwt(username, role, 60*time.Hour)
				if err != nil {
					log.Println("generateJwt error: ", err)
					return nil, err
				}

				if err := userRepo.UpdateRefreshTokenByUsername(newRefreshToken, username); err != nil {
					log.Println("update refreshToken error: ", err)
					return nil, err
				}

				// TODO generate new access token [done]

				newAccessToken, err := generateJwt(username, role, 15*time.Minute)
				if err != nil {
					log.Println("generateJwt error: ", err)
					return nil, err
				}

				// both tokens added to response headers and ready to be sent to backend and returned to frontend
				c.Response().Header().Set("X-Access-Token", newAccessToken)
				c.Response().Header().Set("X-Refresh-Token", newRefreshToken)

				c.Response().Header().Set("Username", username)
				c.Response().Header().Set("Role", role)

				// returning nil because we don't need to parse access token, and going to SuccessHandler
				return nil, nil
			}

			accessToken, err := jwt.ParseWithClaims(auth, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
				return []byte("secret"), nil
			})
			if err != nil {
				log.Println("parse token error: ", err)
				return nil, accessTokenParsingError
			}

			// TODO check if token exp time is still valid [done]

			expiration, ok := accessToken.Claims.(jwt.MapClaims)["exp"].(float64)
			if !ok {
				return nil, accessTokenParsingError
			}

			expirationTime := time.Unix(int64(expiration), 0)
			currentTime := time.Now()

			if currentTime.After(expirationTime) {
				// fetching refresh token from client
				return nil, accessTokenExpired
			}

			// TODO if access token is not expired and valid, then return nil and go to SuccessHandler [done]

			c.Response().Header().Set("Username", accessToken.Claims.(jwt.MapClaims)["username"].(string))
			c.Response().Header().Set("Role", accessToken.Claims.(jwt.MapClaims)["role"].(string))
			c.Response().Header().Set("X-Access-Token", auth)
			c.Response().Header().Set("X-Refresh-Token", "")
			return nil, nil
		},
	}))

	e.POST("/register", func(c echo.Context) error {
		var credentials domain.Credentials

		if err := c.Bind(&credentials); err != nil {
			log.Printf("error while binding credentials: %v\n", err)
			return err
		}

		exists, err := userRepo.CheckIfExists(credentials.Username)
		if err != nil {
			log.Printf("error while checking if user exists: %v\n", err)
			//return err
		}

		if exists {
			log.Println("User exists")
			return c.String(http.StatusUnauthorized, "User exists")
		}

		newRefreshToken, err := generateJwt(credentials.Username, credentials.Role, 60*time.Hour)
		if err != nil {
			log.Println("generateJwt error: ", err)
			return c.String(http.StatusInternalServerError, err.Error())
		}

		newAccessToken, err := generateJwt(credentials.Username, credentials.Role, 15*time.Minute)
		if err != nil {
			log.Println("generateJwt error: ", err)
			return c.String(http.StatusInternalServerError, err.Error())
		}

		if err := userRepo.Save(&entity.User{
			Username:     credentials.Username,
			Password:     credentials.Password,
			Role:         credentials.Role,
			RefreshToken: newRefreshToken,
		}); err != nil {
			log.Printf("error while saving user: %v\n", err)
			return c.String(http.StatusInternalServerError, err.Error())
		}

		c.Response().Header().Set("X-Access-Token", newAccessToken)
		c.Response().Header().Set("X-Refresh-Token", newRefreshToken)
		c.Response().Header().Set("Role", credentials.Role)
		c.Response().Header().Set("Username", credentials.Username)

		return c.String(http.StatusOK, "User created")
	})

	e.POST("/login", func(c echo.Context) error {
		var credentials domain.LoginCredentials

		if err := c.Bind(&credentials); err != nil {
			log.Printf("error while binding login credentials: %v\n", err)
			return err
		}

		exists, err := userRepo.CheckIfExists(credentials.Username)
		if err != nil {
			log.Printf("error while checking if user exists: %v\n", err)
			// return err
		}

		if !exists {
			log.Println("user doesnt exist")
			return c.String(http.StatusUnauthorized, "user doesn't exists")
		}

		role, err := userRepo.GetRoleByUsername(credentials.Username)
		if err != nil {
			log.Println("handler, error fetching role by username")
			return c.String(http.StatusUnauthorized, "error")
		}

		newRefreshToken, err := generateJwt(credentials.Username, role, 60*time.Hour)
		if err != nil {
			log.Println("generateJwt error: ", err)
			return c.String(http.StatusInternalServerError, err.Error())
		}

		newAccessToken, err := generateJwt(credentials.Username, role, 15*time.Minute)
		if err != nil {
			log.Println("generateJwt error: ", err)
			return c.String(http.StatusInternalServerError, err.Error())
		}

		if err := userRepo.UpdateRefreshTokenByUsername(newRefreshToken, credentials.Username); err != nil {
			log.Println("update refreshToken error: ", err)
			return c.String(http.StatusInternalServerError, err.Error())
		}

		c.Response().Header().Set("X-Access-Token", newAccessToken)
		c.Response().Header().Set("X-Refresh-Token", newRefreshToken)
		c.Response().Header().Set("Role", role)
		c.Response().Header().Set("Username", credentials.Username)
		return c.String(http.StatusOK, "loged in")
	})

	e.Logger.Fatal(e.Start(":8080"))
}

// METHOD that do request and wait for it
func handle(c echo.Context) {
	method := c.Request().Method
	url := c.Request().URL.Path
	host := c.Request().Host
	body := c.Request().Body

	request := client.NewRequest()
	request.Method = method
	request.URL = url
	request.Header = map[string][]string{
		"Username": []string{c.Response().Header().Get("Username")},
		"Role":     []string{c.Response().Header().Get("Role")},
	}
	request.Body = body

	fmt.Println("making request to: " + "http://" + host + url)
	resp, err := request.Get("http://localhost:8081" + url)
	if err != nil {
		fmt.Println(err)
		c.String(http.StatusInternalServerError, "proxy error fetching response from back")
	}

	c.String(resp.StatusCode(), string(resp.Body()))
	return
}

func initDb() *gorm.DB {
	//dsn := "host=localhost user=postgres password=password dbname=postgres port=5432 sslmode=disable"
	dsn := "host=c-c9qikb36ojt5s6c7vpfo.rw.mdb.yandexcloud.net user=tsypk password=15.Aleksei dbname=tsypk port=6432 search_path=dev"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		log.Fatalln(err)
	}
	return db
}

func generateJwt(username string, role string, duration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(duration).Unix(),
	})
	return token.SignedString([]byte("secret"))
}
