package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	ErrInvalidToken = errors.New("invalid or expired token")
	ErrMissingAuth  = errors.New("missing authorization header")
)

type AfterSecClaims struct {
	UserID         string `json:"uid"`
	OrganizationID string `json:"org"`
	Role           string `json:"role"`
	jwt.RegisteredClaims
}

type JWTManager struct {
	secretKey     string
	tokenDuration time.Duration
}

func NewJWTManager(secretKey string, duration time.Duration) *JWTManager {
	return &JWTManager{
		secretKey:     secretKey,
		tokenDuration: duration,
	}
}

func (m *JWTManager) GenerateToken(userID, orgID, role string) (string, error) {
	claims := AfterSecClaims{
		UserID:         userID,
		OrganizationID: orgID,
		Role:           role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "aftersec-management-server",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.secretKey))
}

func (m *JWTManager) ValidateToken(tokenStr string) (*AfterSecClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &AfterSecClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(m.secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AfterSecClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func (m *JWTManager) HTTPMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, ErrMissingAuth.Error(), http.StatusUnauthorized)
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, ErrInvalidToken.Error(), http.StatusUnauthorized)
			return
		}
		_, err := m.ValidateToken(parts[1])
		if err != nil {
			http.Error(w, ErrInvalidToken.Error(), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (m *JWTManager) GRPCUnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if err := m.authorizeGRPC(ctx, info.FullMethod); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (m *JWTManager) GRPCStreamInterceptor(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := m.authorizeGRPC(stream.Context(), info.FullMethod); err != nil {
		return err
	}
	return handler(srv, stream)
}

func (m *JWTManager) authorizeGRPC(ctx context.Context, method string) error {
	// Let enroll pass without standard JWT since it uses an enrollment token, 
	// unless we enforce it differently over mTLS
	if strings.HasSuffix(method, "/Enroll") {
		return nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "metadata is not provided")
	}
	values := md["authorization"]
	if len(values) == 0 {
		return status.Errorf(codes.Unauthenticated, "authorization token is not provided")
	}
	authHeader := values[0]
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return status.Errorf(codes.Unauthenticated, "authorization token format is invalid")
	}
	_, err := m.ValidateToken(parts[1])
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "authorization token is invalid: %v", err)
	}
	return nil
}
