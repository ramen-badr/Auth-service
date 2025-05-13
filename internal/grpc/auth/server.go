package auth

import (
	"context"
	"github.com/ramen-badr/Protoc/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"regexp"
)

type Auth interface {
	Login(
		ctx context.Context,
		phone string,
		password string,
		appId int,
	) (string, error)
	Register(
		ctx context.Context,
		name string,
		phone string,
		password string,
	) (int64, error)
	IsAdmin(
		ctx context.Context,
		userID int64,
	) (bool, error)
}

const (
	emptyValue = 0
)

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(
	ctx context.Context,
	req *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {
	if err := validateLogin(req); err != nil {
		return nil, err
	}

	token, err := s.auth.Login(ctx, req.GetPhone(), req.GetPassword(), int(req.GetAppId()))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func validateLogin(req *ssov1.LoginRequest) error {
	re := regexp.MustCompile(`^\+7\d{10}$`)

	if req.GetPhone() == "" {
		return status.Error(codes.InvalidArgument, "phone is required")
	} else if re.MatchString(req.GetPhone()) {
		return status.Error(codes.InvalidArgument, "phone is invalid")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}

	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, "appId is required")
	}

	return nil
}

func (s *serverAPI) Register(
	ctx context.Context,
	req *ssov1.RegisterRequest,
) (*ssov1.RegisterResponse, error) {
	if err := validateRegister(req); err != nil {
		return nil, err
	}

	userID, err := s.auth.Register(ctx, req.GetName(), req.GetPhone(), req.GetPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &ssov1.RegisterResponse{
		UserId: userID,
	}, nil
}

func validateRegister(req *ssov1.RegisterRequest) error {
	re := regexp.MustCompile(`^\+7\d{10}$`)

	if req.GetName() == "" {
		return status.Error(codes.InvalidArgument, "name is required")
	}

	if req.GetPhone() == "" {
		return status.Error(codes.InvalidArgument, "phone is required")
	} else if re.MatchString(req.GetPhone()) {
		return status.Error(codes.InvalidArgument, "phone is invalid")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}

	return nil
}

func (s *serverAPI) IsAdmin(
	ctx context.Context,
	req *ssov1.IsAdminRequest,
) (*ssov1.IsAdminResponse, error) {
	if err := validateIsAdmin(req); err != nil {
		return nil, err
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &ssov1.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}

func validateIsAdmin(req *ssov1.IsAdminRequest) error {
	if req.GetUserId() == emptyValue {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}

	return nil
}
