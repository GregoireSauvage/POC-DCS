package service

import (
	"context"
	"errors"
)

var ErrNotImplemented = errors.New("not implemented")

type CinemaService struct{}

func NewCinemaService() *CinemaService {
	return &CinemaService{}
}

func (s *CinemaService) ListFilms(ctx context.Context) error {
	_ = ctx
	return ErrNotImplemented
}
