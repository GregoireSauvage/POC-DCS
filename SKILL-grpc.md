---
name: grpc-protobuf
# prettier-ignore
description: gRPC et Protocol Buffers pour Go. Utiliser pour définir des fichiers .proto, configurer Buf, générer du code gRPC, implémenter des services, ou gérer le streaming.
---

# gRPC & Protocol Buffers


## Overview

Ce skill couvre la définition des fichiers Protocol Buffers et la génération de code Go avec Buf.

## Structure des fichiers proto

```
proto/
├── user/
│   └── v1/
│       ├── user.proto           # Messages et service
│       └── user_types.proto     # Types partagés (optionnel)
├── order/
│   └── v1/
│       └── order.proto
└── common/
    └── v1/
        └── pagination.proto     # Types réutilisables
```

## Définition d'un service

```protobuf
// proto/user/v1/user.proto
syntax = "proto3";

package user.v1;

import "google/protobuf/timestamp.proto";
import "google/protobuf/empty.proto";
import "common/v1/pagination.proto";

option go_package = "github.com/myorg/myservice/gen/go/user/v1;userv1";

// UserService gère les opérations sur les utilisateurs.
service UserService {
  // GetUser récupère un utilisateur par son ID.
  rpc GetUser(GetUserRequest) returns (GetUserResponse);
  
  // CreateUser crée un nouvel utilisateur.
  rpc CreateUser(CreateUserRequest) returns (CreateUserResponse);
  
  // UpdateUser met à jour un utilisateur existant.
  rpc UpdateUser(UpdateUserRequest) returns (UpdateUserResponse);
  
  // DeleteUser supprime un utilisateur.
  rpc DeleteUser(DeleteUserRequest) returns (google.protobuf.Empty);
  
  // ListUsers liste les utilisateurs avec pagination.
  rpc ListUsers(ListUsersRequest) returns (ListUsersResponse);
  
  // StreamUsers stream les utilisateurs (server streaming).
  rpc StreamUsers(StreamUsersRequest) returns (stream User);
}

// User représente un utilisateur.
message User {
  string id = 1;
  string email = 2;
  string name = 3;
  UserStatus status = 4;
  google.protobuf.Timestamp created_at = 5;
  google.protobuf.Timestamp updated_at = 6;
}

enum UserStatus {
  USER_STATUS_UNSPECIFIED = 0;
  USER_STATUS_ACTIVE = 1;
  USER_STATUS_INACTIVE = 2;
  USER_STATUS_SUSPENDED = 3;
}

// --- Requests & Responses ---

message GetUserRequest {
  string id = 1;
}

message GetUserResponse {
  User user = 1;
}

message CreateUserRequest {
  string email = 1;
  string name = 2;
  string password = 3;  // Ne jamais retourner dans les responses
}

message CreateUserResponse {
  User user = 1;
}

message UpdateUserRequest {
  string id = 1;
  optional string email = 2;
  optional string name = 3;
  optional UserStatus status = 4;
}

message UpdateUserResponse {
  User user = 1;
}

message DeleteUserRequest {
  string id = 1;
}

message ListUsersRequest {
  int32 page_size = 1;
  string page_token = 2;
  string filter = 3;  // Ex: "status=active"
}

message ListUsersResponse {
  repeated User users = 1;
  string next_page_token = 2;
  int32 total_count = 3;
}

message StreamUsersRequest {
  string filter = 1;
}
```

## Configuration Buf

### buf.yaml

```yaml
# buf.yaml
version: v2

modules:
  - path: proto

lint:
  use:
    - DEFAULT
  except:
    - PACKAGE_VERSION_SUFFIX  # Si pas de versioning strict

breaking:
  use:
    - FILE
```

### buf.gen.yaml

```yaml
# buf.gen.yaml
version: v2

managed:
  enabled: true
  override:
    - file_option: go_package_prefix
      value: github.com/myorg/myservice/gen/go

plugins:
  # Messages Protobuf
  - remote: buf.build/protocolbuffers/go
    out: gen/go
    opt:
      - paths=source_relative

  # Services gRPC
  - remote: buf.build/grpc/go
    out: gen/go
    opt:
      - paths=source_relative
      - require_unimplemented_servers=false

inputs:
  - directory: proto
```

### Alternative avec plugins locaux

```yaml
# buf.gen.yaml (plugins locaux)
version: v2

plugins:
  - local: protoc-gen-go
    out: gen/go
    opt:
      - paths=source_relative

  - local: protoc-gen-go-grpc
    out: gen/go
    opt:
      - paths=source_relative
      - require_unimplemented_servers=false

inputs:
  - directory: proto
```

## Commandes Buf

```bash
# Installation
brew install bufbuild/buf/buf

# Initialisation
buf config init

# Génération du code
buf generate

# Linting
buf lint

# Vérification breaking changes
buf breaking --against '.git#branch=main'
buf breaking --against 'buf.build/myorg/myapi'

# Formatage
buf format -w

# Build (vérification sans génération)
buf build
```

## Conventions Proto

### Nommage

```protobuf
// Package: lowercase.avec.points
package user.v1;

// Service: PascalCase + "Service"
service UserService {}

// RPC: PascalCase, verbe + nom
rpc GetUser() {}
rpc CreateUser() {}
rpc ListUsers() {}
rpc DeleteUser() {}

// Messages: PascalCase
message UserRequest {}
message UserResponse {}

// Champs: snake_case
string user_id = 1;
google.protobuf.Timestamp created_at = 2;

// Enums: SCREAMING_SNAKE_CASE avec prefix
enum UserStatus {
  USER_STATUS_UNSPECIFIED = 0;  // Toujours 0 = UNSPECIFIED
  USER_STATUS_ACTIVE = 1;
}
```

### Versioning

```protobuf
// Toujours versionner les packages
package user.v1;      // Version 1
package user.v2;      // Version 2 (breaking changes)

// go_package avec alias court
option go_package = "github.com/myorg/svc/gen/go/user/v1;userv1";
```

### Pagination

```protobuf
// Pattern standard Google AIP
message ListUsersRequest {
  int32 page_size = 1;      // Max items par page
  string page_token = 2;    // Token opaque pour page suivante
}

message ListUsersResponse {
  repeated User users = 1;
  string next_page_token = 2;  // Vide si dernière page
}
```

## Implémentation Go

### Service complet

```go
// internal/service/user_service.go
package service

import (
    "context"
    
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
    "google.golang.org/protobuf/types/known/emptypb"
    "google.golang.org/protobuf/types/known/timestamppb"
    
    userv1 "github.com/myorg/myservice/gen/go/user/v1"
    "github.com/myorg/myservice/internal/domain"
)

type UserRepository interface {
    GetByID(ctx context.Context, id string) (*domain.User, error)
    Create(ctx context.Context, user *domain.User) error
    Update(ctx context.Context, user *domain.User) error
    Delete(ctx context.Context, id string) error
    List(ctx context.Context, pageSize int, pageToken string) ([]*domain.User, string, error)
}

type UserService struct {
    userv1.UnimplementedUserServiceServer
    repo UserRepository
}

func NewUserService(repo UserRepository) *UserService {
    return &UserService{repo: repo}
}

func (s *UserService) GetUser(ctx context.Context, req *userv1.GetUserRequest) (*userv1.GetUserResponse, error) {
    if req.GetId() == "" {
        return nil, status.Error(codes.InvalidArgument, "id is required")
    }
    
    user, err := s.repo.GetByID(ctx, req.GetId())
    if err != nil {
        return nil, status.Errorf(codes.Internal, "failed to get user: %v", err)
    }
    if user == nil {
        return nil, status.Error(codes.NotFound, "user not found")
    }
    
    return &userv1.GetUserResponse{
        User: domainToProto(user),
    }, nil
}

func (s *UserService) CreateUser(ctx context.Context, req *userv1.CreateUserRequest) (*userv1.CreateUserResponse, error) {
    // Validation
    if req.GetEmail() == "" {
        return nil, status.Error(codes.InvalidArgument, "email is required")
    }
    if req.GetName() == "" {
        return nil, status.Error(codes.InvalidArgument, "name is required")
    }
    
    user := &domain.User{
        Email: req.GetEmail(),
        Name:  req.GetName(),
    }
    
    if err := s.repo.Create(ctx, user); err != nil {
        return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
    }
    
    return &userv1.CreateUserResponse{
        User: domainToProto(user),
    }, nil
}

func (s *UserService) DeleteUser(ctx context.Context, req *userv1.DeleteUserRequest) (*emptypb.Empty, error) {
    if req.GetId() == "" {
        return nil, status.Error(codes.InvalidArgument, "id is required")
    }
    
    if err := s.repo.Delete(ctx, req.GetId()); err != nil {
        return nil, status.Errorf(codes.Internal, "failed to delete user: %v", err)
    }
    
    return &emptypb.Empty{}, nil
}

// Conversion helpers
func domainToProto(u *domain.User) *userv1.User {
    return &userv1.User{
        Id:        u.ID,
        Email:     u.Email,
        Name:      u.Name,
        Status:    userv1.UserStatus(u.Status),
        CreatedAt: timestamppb.New(u.CreatedAt),
        UpdatedAt: timestamppb.New(u.UpdatedAt),
    }
}
```

### Server streaming

```go
func (s *UserService) StreamUsers(req *userv1.StreamUsersRequest, stream userv1.UserService_StreamUsersServer) error {
    ctx := stream.Context()
    
    users, err := s.repo.ListAll(ctx, req.GetFilter())
    if err != nil {
        return status.Errorf(codes.Internal, "failed to list users: %v", err)
    }
    
    for _, user := range users {
        // Vérifier si le client a annulé
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }
        
        if err := stream.Send(domainToProto(user)); err != nil {
            return err
        }
    }
    
    return nil
}
```

## Tests gRPC

```go
// internal/service/user_service_test.go
package service_test

import (
    "context"
    "testing"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
    
    userv1 "github.com/myorg/myservice/gen/go/user/v1"
    "github.com/myorg/myservice/internal/domain"
    "github.com/myorg/myservice/internal/service"
)

type mockUserRepository struct {
    user *domain.User
    err  error
}

func (m *mockUserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
    return m.user, m.err
}

func TestUserService_GetUser(t *testing.T) {
    t.Run("success", func(t *testing.T) {
        repo := &mockUserRepository{
            user: &domain.User{ID: "123", Name: "Alice", Email: "alice@test.com"},
        }
        svc := service.NewUserService(repo)
        
        resp, err := svc.GetUser(context.Background(), &userv1.GetUserRequest{Id: "123"})
        
        require.NoError(t, err)
        assert.Equal(t, "123", resp.User.Id)
        assert.Equal(t, "Alice", resp.User.Name)
    })
    
    t.Run("not found", func(t *testing.T) {
        repo := &mockUserRepository{user: nil}
        svc := service.NewUserService(repo)
        
        _, err := svc.GetUser(context.Background(), &userv1.GetUserRequest{Id: "unknown"})
        
        require.Error(t, err)
        st, ok := status.FromError(err)
        require.True(t, ok)
        assert.Equal(t, codes.NotFound, st.Code())
    })
    
    t.Run("invalid argument - empty id", func(t *testing.T) {
        svc := service.NewUserService(nil)
        
        _, err := svc.GetUser(context.Background(), &userv1.GetUserRequest{})
        
        require.Error(t, err)
        st, _ := status.FromError(err)
        assert.Equal(t, codes.InvalidArgument, st.Code())
    })
}
```

## Tools utiles

```bash
# grpcurl - CLI pour tester
brew install grpcurl

grpcurl -plaintext localhost:50051 list
grpcurl -plaintext localhost:50051 describe user.v1.UserService
grpcurl -plaintext -d '{"id":"123"}' localhost:50051 user.v1.UserService/GetUser

# evans - REPL interactif
brew install evans
evans --host localhost --port 50051 -r repl

# buf
buf lint
buf generate
```
