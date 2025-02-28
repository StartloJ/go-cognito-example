package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	cognitoClient "lab_cognito/utils"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

type UserResponse struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	CustomID      string `json:"custom_id"`
	EmailVerified bool   `json:"email_verified"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}
	cognitoClient := cognitoClient.NewCognitoClient(os.Getenv("COGNITO_CLIENT_ID"))
	r := gin.Default()

	r.POST("user/login", func(context *gin.Context) {
		token, err := SignIn(context, cognitoClient)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		context.JSON(http.StatusCreated, gin.H{
			"access_token": token.AccessToken,
			"id_token":     token.IdToken,
		})
	})
	r.GET("user", func(context *gin.Context) {
		user, err := GetUserByToken(context, cognitoClient)
		if err != nil {
			if err.Error() == "token not found" {
				context.JSON(http.StatusUnauthorized, gin.H{"error": "token not found"})
				return
			}
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		context.JSON(http.StatusOK, gin.H{"user": user})
	})

	fmt.Println("Server is running on port 8080")
	err = r.Run(":8080")
	if err != nil {
		panic(err)
	}
}

func SignIn(c *gin.Context, cognito cognitoClient.CognitoInterface) (*cognitoClient.UserAuth, error) {
	var user cognitoClient.UserLogin
	if err := c.ShouldBindJSON(&user); err != nil {
		return nil, errors.New("invalid json")
	}
	tokens, err := cognito.SignIn(&user)
	if err != nil {
		return nil, errors.New("could not sign in")
	}
	return tokens, nil
}

func GetUserByToken(c *gin.Context, cognito cognitoClient.CognitoInterface) (*UserResponse, error) {
	token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if token == "" {
		return nil, errors.New("token not found")
	}
	cognitoUser, err := cognito.GetUserByToken(token)
	if err != nil {
		return nil, errors.New("could not get user")
	}
	user := &UserResponse{}
	for _, attribute := range cognitoUser.UserAttributes {
		switch *attribute.Name {
		case "sub":
			user.ID = *attribute.Value
		case "name":
			user.Name = *attribute.Value
		case "email":
			user.Email = *attribute.Value
		case "custom:custom_id":
			user.CustomID = *attribute.Value
		case "email_verified":
			emailVerified, err := strconv.ParseBool(*attribute.Value)
			if err == nil {
				user.EmailVerified = emailVerified
			}
		}
	}
	return user, nil
}
