package auth

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/lib/logger/handlers/sLogger"
	"sso/internal/storage"
	"time"
)

type Auth struct {
	log          *slog.Logger
	UserSaver    UserSaver
	UserProvider UserProvider
	AppProvider  AppProvider
	TokenTTL     time.Duration
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		name string,
		phone string,
		passHash []byte,
	) (int64, error)
}

type UserProvider interface {
	User(ctx context.Context, phone string) (models.User, error)
	IsAdmin(ctx context.Context, userId int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appId int) (models.App, error)
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAppId       = errors.New("invalid app id")
	ErrUserAlreadyExists  = errors.New("user already exists")
)

func New(
	log *slog.Logger,
	userProvider UserProvider,
	userSaver UserSaver,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		log,
		userSaver,
		userProvider,
		appProvider,
		tokenTTL,
	}
}

func (a *Auth) Login(
	ctx context.Context,
	phone string,
	password string,
	appID int,
) (string, error) {
	const op = "auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("phone", phone),
	)

	log.Info("attempting to login user")

	user, err := a.UserProvider.User(ctx, phone)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sLogger.Error(err))
			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}
		log.Error("failed to get user", sLogger.Error(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err = bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Error("invalid credentials", sLogger.Error(err))
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.AppProvider.App(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	token, err := jwt.NewToken(user, app, a.TokenTTL)
	if err != nil {
		log.Error("failed to generate token", sLogger.Error(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (a *Auth) Register(
	ctx context.Context,
	name string,
	phone string,
	password string,
) (int64, error) {
	const op = "auth.Register"

	log := a.log.With(
		slog.String("op", op),
		slog.String("name", name),
		slog.String("phone", phone),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		if errors.Is(err, storage.ErrUserAlreadyExists) {
			log.Warn("user already exists", sLogger.Error(err))
			return 0, fmt.Errorf("%s: %w", op, ErrUserAlreadyExists)
		}
		log.Error("failed to hash password", sLogger.Error(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.UserSaver.SaveUser(ctx, name, phone, passHash)
	if err != nil {
		log.Error("failed to save user", sLogger.Error(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("registered user")

	return id, nil
}

func (a *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "Auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("checking if user is admin")

	isAdmin, err := a.UserProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("user not found", sLogger.Error(err))
			return false, fmt.Errorf("%s: %w", op, ErrInvalidAppId)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if user is admin", slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}
