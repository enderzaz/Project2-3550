package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func setupTestServer(t *testing.T) (*Server, string) {
	tmpFile, err := os.CreateTemp("", "test_keys_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp db file: %v", err)
	}
	tmpFile.Close()

	server, err := NewServer(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	return server, tmpFile.Name()
}

func TestNewServerInvalidPath(t *testing.T) {
	_, err := NewServer("/nonexistent/path/to/db.db")
	if err == nil {
		t.Error("Expected error when opening database with invalid path, got nil")
	}
}

func TestEnsureInitialKeysError(t *testing.T) {
	server, dbPath := setupTestServer(t)
	server.db.Close()
	os.Remove(dbPath)

	err := server.ensureInitialKeys()
	if err == nil {
		t.Error("Expected error when database is closed, got nil")
	}
}

func TestJWKSHandler(t *testing.T) {
	server, dbPath := setupTestServer(t)
	defer os.Remove(dbPath)
	defer server.db.Close()

	req, _ := http.NewRequest("GET", "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.JWKSHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status 200, got %v", status)
	}

	var response JWKS
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse JWKS JSON: %v", err)
	}

	if len(response.Keys) != 1 {
		t.Errorf("Expected exactly 1 valid key, got %d", len(response.Keys))
	}
}

func TestJWKSHandlerQueryError(t *testing.T) {
	server, dbPath := setupTestServer(t)
	defer os.Remove(dbPath)
	server.db.Close()

	req, _ := http.NewRequest("GET", "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.JWKSHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("Expected status 500 when DB is closed, got %v", status)
	}
}

func TestJWKSHandlerMalformedKey(t *testing.T) {
	server, dbPath := setupTestServer(t)
	defer os.Remove(dbPath)
	defer server.db.Close()

	_, err := server.db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", []byte("not-a-pem"), 4102444800)
	if err != nil {
		t.Fatalf("Failed to insert malformed key: %v", err)
	}

	req, _ := http.NewRequest("GET", "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.JWKSHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status 200, got %v", status)
	}
}

func TestAuthHandlerValidKey(t *testing.T) {
	server, dbPath := setupTestServer(t)
	defer os.Remove(dbPath)
	defer server.db.Close()

	req, _ := http.NewRequest("POST", "/auth", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.AuthHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status 200, got %v", status)
	}

	var response map[string]string
	json.Unmarshal(rr.Body.Bytes(), &response)

	tokenStr, exists := response["token"]
	if !exists {
		t.Fatal("Response missing token")
	}

	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("Failed to parse JWT: %v", err)
	}

	if _, ok := token.Header["kid"].(string); !ok {
		t.Error("JWT missing string 'kid' header")
	}
}

func TestAuthHandlerExpiredKey(t *testing.T) {
	server, dbPath := setupTestServer(t)
	defer os.Remove(dbPath)
	defer server.db.Close()

	req, _ := http.NewRequest("POST", "/auth?expired=true", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.AuthHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status 200, got %v", status)
	}
}

func TestAuthHandlerNoKeyFound(t *testing.T) {
	server, dbPath := setupTestServer(t)
	defer os.Remove(dbPath)
	defer server.db.Close()

	_, _ = server.db.Exec("DELETE FROM keys")

	req, _ := http.NewRequest("POST", "/auth", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.AuthHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("Expected status 500 when no keys exist, got %v", status)
	}
}

func TestAuthHandlerMalformedKey(t *testing.T) {
	server, dbPath := setupTestServer(t)
	defer os.Remove(dbPath)
	defer server.db.Close()

	_, _ = server.db.Exec("DELETE FROM keys")
	_, err := server.db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", []byte("not-a-pem"), 4102444800)
	if err != nil {
		t.Fatalf("Failed to insert malformed key: %v", err)
	}

	req, _ := http.NewRequest("POST", "/auth", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.AuthHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("Expected status 500 for malformed key, got %v", status)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	server, dbPath := setupTestServer(t)
	defer os.Remove(dbPath)
	defer server.db.Close()

	req1, _ := http.NewRequest("POST", "/.well-known/jwks.json", nil)
	rr1 := httptest.NewRecorder()
	http.HandlerFunc(server.JWKSHandler).ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 for POST /jwks, got %v", rr1.Code)
	}

	req2, _ := http.NewRequest("GET", "/auth", nil)
	rr2 := httptest.NewRecorder()
	http.HandlerFunc(server.AuthHandler).ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 for GET /auth, got %v", rr2.Code)
	}
}
