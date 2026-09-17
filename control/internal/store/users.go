package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

var ErrNotFound = errors.New("not found")
var ErrBadCredentials = errors.New("wrong username or password")

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) CreateUser(ctx context.Context, username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO users (username, password_hash) VALUES ($1, $2)
		 ON CONFLICT (username) DO NOTHING`, username, string(hash))
	return err
}

// Authenticate kiem tra mat khau, tra ve User khi dung.
func (s *Store) Authenticate(ctx context.Context, username, password string) (*User, error) {
	var u User
	var hash string
	err := s.pool.QueryRow(ctx,
		`SELECT id, username, password_hash, created_at FROM users WHERE username = $1`,
		username).Scan(&u.ID, &u.Username, &hash, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// still run bcrypt once so response time does not reveal whether the account exists
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidin"), []byte(password))
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return nil, ErrBadCredentials
	}
	return &u, nil
}

func (s *Store) GetUser(ctx context.Context, id int64) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, username, created_at FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Username, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

// PasswordChangedAt reports when this account's credentials last changed. A token
// minted before that moment must no longer be accepted.
func (s *Store) PasswordChangedAt(ctx context.Context, id int64) (time.Time, error) {
	var t time.Time
	err := s.pool.QueryRow(ctx, `SELECT updated_at FROM users WHERE id = $1`, id).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

func (s *Store) SetPassword(ctx context.Context, username, password string) error {
	if len(password) < 8 {
		return fmt.Errorf("the password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET password_hash = $2, updated_at = now() WHERE username = $1`,
		username, string(hash))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
