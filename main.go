package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

const dbFileName = "totally_not_my_privateKeys.db"

type Server struct {
	db *sql.DB
	mu sync.Mutex
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func NewServer(dbPath string) (*Server, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	createTableQuery := `
	CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);
	`
	if _, err := db.Exec(createTableQuery); err != nil {
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	s := &Server{db: db}
	if err := s.ensureInitialKeys(); err != nil {
		return nil, fmt.Errorf("failed to ensure initial keys: %w", err)
	}

	return s, nil
}

func (s *Server) ensureInitialKeys() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		if err := s.generateAndSaveKey(time.Now().Add(24 * time.Hour)); err != nil {
			return err
		}
		if err := s.generateAndSaveKey(time.Now().Add(-1 * time.Hour)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) generateAndSaveKey(expiry time.Time) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	derBytes := x509.MarshalPKCS1PrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derBytes,
	})

	_, err = s.db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", pemBytes, expiry.Unix())
	return err
}

func (s *Server) JWKSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().Unix()
	rows, err := s.db.Query("SELECT kid, key, exp FROM keys WHERE exp > ?", now)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var validKeys []JWK

	for rows.Next() {
		var kid int
		var keyBlob []byte
		var exp int64

		if err := rows.Scan(&kid, &keyBlob, &exp); err != nil {
			continue
		}

		block, _ := pem.Decode(keyBlob)
		if block == nil {
			continue
		}

		privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			continue
		}

		pubKey := &privKey.PublicKey
		nStr := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
		eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes())

		validKeys = append(validKeys, JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: fmt.Sprintf("%d", kid),
			N:   nStr,
			E:   eStr,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JWKS{Keys: validKeys})
}

func (s *Server) AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_ = r.ParseForm()

	useExpired := r.URL.Query().Has("expired")
	now := time.Now().Unix()

	var query string
	if useExpired {
		query = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1"
	} else {
		query = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1"
	}

	var kid int
	var keyBlob []byte
	var exp int64

	err := s.db.QueryRow(query, now).Scan(&kid, &keyBlob, &exp)
	if err != nil {
		http.Error(w, "No suitable key found to sign token", http.StatusInternalServerError)
		return
	}

	block, _ := pem.Decode(keyBlob)
	if block == nil {
		http.Error(w, "Failed to decode private key", http.StatusInternalServerError)
		return
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		http.Error(w, "Failed to parse private key", http.StatusInternalServerError)
		return
	}

	tokenExpiry := time.Now().Add(1 * time.Hour)
	if useExpired {
		tokenExpiry = time.Now().Add(-1 * time.Hour)
	}

	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "jwks-auth-server",
		"exp": tokenExpiry.Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = fmt.Sprintf("%d", kid)

	signedString, err := token.SignedString(privKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": signedString,
	})
}

func main() {
	server, err := NewServer(dbFileName)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}
	defer server.db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", server.JWKSHandler)
	mux.HandleFunc("/auth", server.AuthHandler)

	port := "8080"
	log.Printf("JWKS Server listening on http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
