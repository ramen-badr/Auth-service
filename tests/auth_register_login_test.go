package tests

import (
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ramen-badr/Protoc/gen/go/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sso/tests/suite"
	"testing"
	"time"
)

const (
	emptyAppID     = 0
	appID          = 1
	appSecret      = "secret"
	passDefaultLen = 10
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	phone := gofakeit.Phone()
	name := gofakeit.Name()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Name:     name,
		Phone:    phone,
		Password: pass,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Phone:    phone,
		Password: pass,
		AppId:    appID,
	})
	require.NoError(t, err)

	token := respLogin.GetToken()
	require.NotEmpty(t, token)

	loginTime := time.Now()

	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, respReg.GetUserId(), int64(claims["uid"].(float64)))
	assert.Equal(t, name, claims["name"].(string))
	assert.Equal(t, phone, claims["phone"].(string))
	assert.Equal(t, appID, int(claims["app_id"].(float64)))

	const deltaSeconds = 1

	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"].(float64), deltaSeconds)
}

func TestRegisterLogin_DuplicatedRegistration(t *testing.T) {
	ctx, st := suite.New(t)

	phone := gofakeit.Phone()
	name := gofakeit.Name()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Name:     name,
		Phone:    phone,
		Password: pass,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())

	respReg, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Name:     name,
		Phone:    phone,
		Password: pass,
	})
	require.Error(t, err)
	assert.Empty(t, respReg.GetUserId())
	assert.ErrorContains(t, err, "user already exists")
}

func TestRegister_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		userName    string
		phone       string
		password    string
		expectedErr string
	}{
		{
			name:        "Register with Empty Password",
			userName:    "Alice",
			phone:       gofakeit.Email(),
			password:    "",
			expectedErr: "password is required",
		},
		{
			name:        "Register with Empty Email",
			userName:    "Alice2",
			phone:       "",
			password:    randomFakePassword(),
			expectedErr: "phone is required",
		},
		{
			name:        "Register with Both Empty",
			userName:    "Alice3",
			phone:       "",
			password:    "",
			expectedErr: "phone is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Name:     tt.userName,
				Phone:    tt.phone,
				Password: tt.password,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)

		})
	}
}

func TestLogin_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		userName    string
		phone       string
		password    string
		appID       int32
		expectedErr string
	}{
		{
			name:        "Login with Empty Password",
			userName:    "Alice2",
			phone:       gofakeit.Phone(),
			password:    "",
			appID:       appID,
			expectedErr: "password is required",
		},
		{
			name:        "Login with Empty Email",
			userName:    "Alice2",
			phone:       "",
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "phone is required",
		},
		{
			name:        "Login with Both Empty Email and Password",
			userName:    "Alice2",
			phone:       "",
			password:    "",
			appID:       appID,
			expectedErr: "phone is required",
		},
		{
			name:        "Login with Non-Matching Password",
			userName:    "Alice2",
			phone:       gofakeit.Phone(),
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "invalid credentials",
		},
		{
			name:        "Login without AppID",
			userName:    "Alice2",
			phone:       gofakeit.Phone(),
			password:    randomFakePassword(),
			appID:       emptyAppID,
			expectedErr: "appId is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Name:     tt.userName,
				Phone:    gofakeit.Phone(),
				Password: randomFakePassword(),
			})
			require.NoError(t, err)

			_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
				Phone:    tt.phone,
				Password: tt.password,
				AppId:    tt.appID,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}
