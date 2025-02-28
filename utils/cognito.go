package cognitoClient

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

type User struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"email"`
	Username string `json:"username" binding:"required,username"`
	Password string `json:"password" binding:"required"`
}

type UserAuth struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
}

type CognitoInterface interface {
	SignUp(user *User) error
	SignIn(user *UserLogin) (*UserAuth, error)
	GetUserByToken(token string) (*cognito.GetUserOutput, error)
	UpdatePassword(user *UserLogin) error
}

type UserLogin struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type cognitoClient struct {
	cognitoClient *cognito.CognitoIdentityProvider
	appClientID   string
}

type GetUserOutput struct {
	_                   struct{}  `type:"structure"`
	PreferredMfaSetting *string   `type:"string"`
	UserMFASettingList  []*string `type:"list"`
	Username            *string   `min:"1" type:"string" required:"true" sensitive:"true"`
}

func GenerateMsgDigest(msg, key []byte) (string, error) {
	h := hmac.New(sha256.New, key)
	_, err := h.Write(msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func NewCognitoClient(appClientId string) CognitoInterface {
	config := &aws.Config{Region: aws.String("ap-southeast-1")}
	sess, err := session.NewSession(config)
	if err != nil {
		panic(err)
	}
	client := cognito.New(sess)

	return &cognitoClient{
		cognitoClient: client,
		appClientID:   appClientId,
	}
}

func (c *cognitoClient) SignUp(user *User) error {
	return nil
}

func (c *cognitoClient) SignIn(user *UserLogin) (*UserAuth, error) {
	clientSecret := os.Getenv("COGNITO_CLIENT_SECRET")
	secretHash, err := GenerateMsgDigest([]byte(user.Username+os.Getenv("COGNITO_CLIENT_ID")), []byte(clientSecret))
	if err != nil {
		return nil, err
	}
	authInput := &cognito.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		AuthParameters: aws.StringMap(map[string]string{
			"USERNAME":    user.Username,
			"PASSWORD":    user.Password,
			"SECRET_HASH": secretHash,
		}),
		ClientId: aws.String(c.appClientID),
	}
	result, err := c.cognitoClient.InitiateAuth(authInput)
	if err != nil {
		return nil, err
	}

	userAuth := &UserAuth{
		AccessToken:  *result.AuthenticationResult.AccessToken,
		ExpiresIn:    int(*result.AuthenticationResult.ExpiresIn),
		TokenType:    *result.AuthenticationResult.TokenType,
		RefreshToken: *result.AuthenticationResult.RefreshToken,
		IdToken:      *result.AuthenticationResult.IdToken,
	}
	return userAuth, nil
}

func (c *cognitoClient) GetUserByToken(token string) (*cognito.GetUserOutput, error) {
	input := &cognito.GetUserInput{
		AccessToken: aws.String(token),
	}
	result, err := c.cognitoClient.GetUser(input)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *cognitoClient) UpdatePassword(user *UserLogin) error {
	input := &cognito.AdminSetUserPasswordInput{
		UserPoolId: aws.String(os.Getenv("COGNITO_USER_POOL_ID")),
		Username:   aws.String(user.Username),
		Password:   aws.String(user.Password),
		Permanent:  aws.Bool(true),
	}
	_, err := c.cognitoClient.AdminSetUserPassword(input)
	if err != nil {
		return err
	}
	return nil
}
