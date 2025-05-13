package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sso/internal/domain/models"
	"time"
)

func NewToken(
	user models.User,
	app models.App,
	duration time.Duration,
) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = user.ID
	claims["name"] = user.Name
	claims["phone"] = user.Phone
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = app.Id

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", status.Error(codes.Internal, err.Error())
	}

	return tokenString, nil
}
