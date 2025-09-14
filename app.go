package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

//go:embed public/*
var publicFiles embed.FS

// emebed fs my beloved

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

type App struct {
	DB          *gorm.DB
	Config      *Config
	RateLimiter *rate.Limiter
	AuthLimiter *rate.Limiter
	CSRFTokens  map[string]time.Time
	CSRFMutex   sync.RWMutex
}

type Config struct {
	SocketPath     string
	DataDir        string
	MaxFileSize    int64
	MaxStorageSize int64
	MasterKey      string
	JWTSecret      string
}

type File struct {
	ID              string    `gorm:"primaryKey" json:"id"`
	Token           string    `gorm:"uniqueIndex" json:"token"`
	Filename        string    `json:"filename"`
	Size            int64     `json:"size"`
	MimeType        string    `json:"mime_type"`
	PersonalTokenID string    `json:"personal_token_id"`
	CreatedAt       time.Time `json:"created_at"`
}

type PersonalToken struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	Token     string    `gorm:"uniqueIndex" json:"token"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
}

type Lockdown struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	Type      string    `json:"type"`  // "user" или "all"
	Token     string    `json:"token"` // для user типа
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

type TokenClaims struct {
	FileID string `json:"file_id"`
	jwt.RegisteredClaims
}

func generateSecureToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback к времени если криптографический генератор недоступен, говно, но пусть будет
		for i := range b {
			b[i] = charset[int(time.Now().UnixNano())%len(charset)]
		}
	} else {
		for i := range b {
			b[i] = charset[b[i]%byte(len(charset))]
		}
	}
	return string(b)
}

func validateFilePath(baseDir, fileID string) (string, error) {
	if len(fileID) == 0 || len(fileID) > 100 {
		return "", fmt.Errorf("invalid file ID length")
	}

	cleanPath := filepath.Clean(fileID)
	if strings.Contains(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") || strings.Contains(cleanPath, "\\") {
		return "", fmt.Errorf("invalid file path")
	}

	matched, _ := regexp.MatchString(`^[a-f0-9-]{36}$`, fileID)
	if !matched {
		return "", fmt.Errorf("invalid file ID format")
	}

	fullPath := filepath.Join(baseDir, "files", cleanPath)

	// сегодня без curl https://penis.rf/../../../../../etc/passwd
	basePath := filepath.Join(baseDir, "files")
	relPath, err := filepath.Rel(basePath, fullPath)
	if err != nil || strings.HasPrefix(relPath, "..") {
		return "", fmt.Errorf("path traversal detected")
	}

	return fullPath, nil
}

func validateMimeType(content []byte, declaredMime string) bool {
	if len(content) == 0 {
		return false
	}

	detectedMime := http.DetectContentType(content)

	// огонь по блядскому хутору, а если срз,
	// то хоть шанс что кто-то закинет сюда вирусню и будет ее так распространять -
	// дико мал
	blockedMimes := map[string]bool{
		"application/x-executable": true,
		"application/x-msdownload": true,
		"application/x-sh":         true,
	}

	return !blockedMimes[detectedMime]
}

func sanitizeFilename(filename string) string {
	filename = strings.TrimSpace(filename)
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")
	filename = strings.ReplaceAll(filename, "..", "_")
	if len(filename) > 255 {
		filename = filename[:255]
	}
	return filename
}

func NewApp() *App {
	config := &Config{
		SocketPath:     getEnv("MBOX_SOCKET_PATH", "/var/run/mkbox.sock"),
		DataDir:        getEnv("MBOX_DATA_DIR", "/var/lib/mkbox"),
		MaxFileSize:    150 * 1024 * 1024 * 1024, // 150GB
		MaxStorageSize: 20 * 1024 * 1024 * 1024,  // 20GB
	}

	os.MkdirAll(config.DataDir, 0755)
	os.MkdirAll(filepath.Dir(config.SocketPath), 0755)

	db, err := gorm.Open(sqlite.Open(filepath.Join(config.DataDir, "db.sqlite")), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	db.AutoMigrate(&File{}, &PersonalToken{}, &Lockdown{})

	app := &App{
		DB:          db,
		Config:      config,
		RateLimiter: rate.NewLimiter(rate.Limit(10), 20),
		AuthLimiter: rate.NewLimiter(rate.Limit(5), 10), // 5 запросов в секунду, burst 10
		CSRFTokens:  make(map[string]time.Time),
	}

	app.loadConfig()

	go app.cleanupCSRFTokens()

	return app
}

func (app *App) loadConfig() {
	configPath := filepath.Join(app.Config.DataDir, "config")
	if data, err := os.ReadFile(configPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				switch parts[0] {
				case "MASTER_KEY":
					app.Config.MasterKey = parts[1]
				case "JWT_SECRET":
					app.Config.JWTSecret = parts[1]
				case "MAX_FILE_SIZE":
					if size, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						app.Config.MaxFileSize = size
					}
				case "MAX_STORAGE_SIZE":
					if size, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						app.Config.MaxStorageSize = size
					}
				}
			}
		}
	}

	if app.Config.MasterKey == "" {
		key := make([]byte, 32)
		rand.Read(key)
		app.Config.MasterKey = hex.EncodeToString(key)
		app.saveConfig()
	}

	if app.Config.JWTSecret == "" {
		secret := make([]byte, 32)
		rand.Read(secret)
		app.Config.JWTSecret = hex.EncodeToString(secret)
		app.saveConfig()
	}
}

func (app *App) saveConfig() {
	config := fmt.Sprintf("MASTER_KEY=%s\nJWT_SECRET=%s\nMAX_FILE_SIZE=%d\nMAX_STORAGE_SIZE=%d\n",
		app.Config.MasterKey, app.Config.JWTSecret, app.Config.MaxFileSize, app.Config.MaxStorageSize)
	os.WriteFile(filepath.Join(app.Config.DataDir, "config"), []byte(config), 0600)
}

func (app *App) cleanupCSRFTokens() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		app.CSRFMutex.Lock()
		for token, expiry := range app.CSRFTokens {
			if now.After(expiry) {
				delete(app.CSRFTokens, token)
			}
		}
		app.CSRFMutex.Unlock()
	}
}

func (app *App) cleanupOldFiles() {
	var totalSize int64
	if err := app.DB.Model(&File{}).Select("COALESCE(SUM(size), 0)").Scan(&totalSize).Error; err != nil {
		return
	}

	if totalSize <= app.Config.MaxStorageSize {
		return
	}

	var files []File
	if err := app.DB.Order("created_at ASC").Find(&files).Error; err != nil {
		return
	}

	excessSize := totalSize - app.Config.MaxStorageSize
	deletedSize := int64(0)

	for _, file := range files {
		if deletedSize >= excessSize {
			break
		}

		filePath := filepath.Join(app.Config.DataDir, "files", file.ID)
		os.Remove(filePath)
		app.DB.Delete(&file)
		deletedSize += file.Size
	}
}

func (app *App) Run() {
	e := echo.New()
	e.HideBanner = true

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(app.rateLimitMiddleware())
	e.Use(middleware.Secure())

	e.Static("/files", filepath.Join(app.Config.DataDir, "files"))

	// Встроенные статические файлы
	e.GET("/style.css", app.handleStatic("public/style.css"))
	e.GET("/background.js", app.handleStatic("public/background.js"))
	e.GET("/end-portal-*.png", app.handlePNG)
	e.GET("/", app.handleIndex)
	e.GET("/csrf-token", app.handleCSRFToken)
	e.POST("/auth", app.handleAuth, app.authRateLimitMiddleware(), app.csrfMiddleware())
	e.POST("/create-token", app.handleCreateToken, app.authRateLimitMiddleware(), app.csrfMiddleware())
	e.POST("/upload", app.handleUpload, app.authMiddleware, app.csrfMiddleware())
	e.GET("/files/:id", app.handleDownload)
	e.DELETE("/files/:id", app.handleDelete, app.authMiddleware, app.csrfMiddleware())
	e.GET("/api/files", app.handleListFiles, app.authMiddleware)
	e.GET("/api/stats", app.handleStats, app.authMiddleware)

	var listener net.Listener
	var err error

	if strings.HasPrefix(app.Config.SocketPath, ":") {
		listener, err = net.Listen("tcp", app.Config.SocketPath)
		log.Printf("mkboxd listening on %s", app.Config.SocketPath)
	} else {
		listener, err = net.Listen("unix", app.Config.SocketPath)
		log.Printf("mkboxd listening on %s", app.Config.SocketPath)
	}

	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.Serve(listener, e))
}

func (app *App) handleIndex(c echo.Context) error {
	data, err := publicFiles.ReadFile("public/index.html")
	if err != nil {
		return c.String(500, "Internal Server Error")
	}
	return c.HTMLBlob(200, data)
}

func (app *App) handleCSRFToken(c echo.Context) error {
	token := generateSecureToken(32)
	app.CSRFMutex.Lock()
	app.CSRFTokens[token] = time.Now().Add(1 * time.Hour)
	app.CSRFMutex.Unlock()
	return c.JSON(200, map[string]string{"token": token})
}

func (app *App) handleStatic(path string) echo.HandlerFunc {
	return func(c echo.Context) error {
		data, err := publicFiles.ReadFile(path)
		if err != nil {
			return c.String(404, "Not Found")
		}

		contentType := "text/plain"
		if strings.HasSuffix(path, ".css") {
			contentType = "text/css"
		} else if strings.HasSuffix(path, ".js") {
			contentType = "application/javascript"
		} else if strings.HasSuffix(path, ".html") {
			contentType = "text/html"
		} else if strings.HasSuffix(path, ".json") {
			contentType = "application/json"
		}

		return c.Blob(200, contentType, data)
	}
}

func (app *App) handlePNG(c echo.Context) error {
	data, err := publicFiles.ReadFile("public/end-portal-GA2RFWBM.png")
	if err != nil {
		return c.String(404, "Not Found")
	}
	return c.Blob(200, "image/png", data)
}

func (app *App) handleListFiles(c echo.Context) error {
	var files []File
	if err := app.DB.Find(&files).Error; err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to list files"})
	}
	return c.JSON(200, files)
}

func (app *App) handleStats(c echo.Context) error {
	var count int64
	var totalSize int64

	if err := app.DB.Model(&File{}).Count(&count).Error; err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to count files"})
	}

	if err := app.DB.Model(&File{}).Select("COALESCE(SUM(size), 0)").Scan(&totalSize).Error; err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to calculate total size"})
	}

	return c.JSON(200, map[string]interface{}{
		"file_count": count,
		"total_size": totalSize,
	})
}

func (app *App) handleAuth(c echo.Context) error {
	var req struct {
		Key string `json:"key"`
	}
	if err := c.Bind(&req); err != nil {
		log.Printf("SECURITY: Invalid auth request from %s: %v", c.RealIP(), err)
		return c.JSON(400, map[string]string{"error": "Invalid request"})
	}

	if req.Key != app.Config.MasterKey {
		log.Printf("SECURITY: Failed auth attempt from %s", c.RealIP())
		return c.JSON(401, map[string]string{"error": "Invalid key"})
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	})

	tokenString, err := token.SignedString([]byte(app.Config.JWTSecret))
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to create token"})
	}

	return c.JSON(200, map[string]string{"token": tokenString})
}

func (app *App) handleUpload(c echo.Context) error {
	var globalLockdown Lockdown
	if err := app.DB.Where("type = ?", "all").First(&globalLockdown).Error; err == nil {
		return c.JSON(403, map[string]string{"error": "Uploads are disabled", "message": globalLockdown.Message})
	}

	personalToken := c.Request().Header.Get("X-Personal-Token")
	var personalTokenRecord PersonalToken
	var personalTokenID string

	if personalToken != "" {
		if len(personalToken) > 100 {
			return c.JSON(400, map[string]string{"error": "Invalid personal token"})
		}

		var userLockdown Lockdown
		if err := app.DB.Where("type = ? AND token = ?", "user", personalToken).First(&userLockdown).Error; err == nil {
			return c.JSON(403, map[string]string{"error": "User uploads are disabled", "message": userLockdown.Message})
		}

		if err := app.DB.Where("token = ?", personalToken).First(&personalTokenRecord).Error; err != nil {
			return c.JSON(401, map[string]string{"error": "Invalid personal token"})
		}
		personalTokenID = personalTokenRecord.ID
	} else {
		tempToken := generateSecureToken(32)
		clientIP := c.RealIP()

		personalTokenRecord = PersonalToken{
			ID:        uuid.New().String(),
			Token:     tempToken,
			IP:        clientIP,
			CreatedAt: time.Now(),
		}

		if err := app.DB.Create(&personalTokenRecord).Error; err != nil {
			return c.JSON(500, map[string]string{"error": "Failed to create temporary token"})
		}
		personalTokenID = personalTokenRecord.ID
	}

	file, err := c.FormFile("file")
	if err != nil {
		return c.JSON(400, map[string]string{"error": "No file provided"})
	}

	if file.Size > app.Config.MaxFileSize {
		return c.JSON(400, map[string]string{"error": "File too large"})
	}

	if file.Size <= 0 {
		return c.JSON(400, map[string]string{"error": "Empty file not allowed"})
	}

	sanitizedFilename := sanitizeFilename(file.Filename)
	if sanitizedFilename == "" {
		return c.JSON(400, map[string]string{"error": "Invalid filename"})
	}

	src, err := file.Open()
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to open file"})
	}
	defer src.Close()

	fileContent := make([]byte, file.Size)
	bytesRead, err := io.ReadFull(src, fileContent)
	if err != nil || int64(bytesRead) != file.Size {
		return c.JSON(400, map[string]string{"error": "File size mismatch"})
	}

	declaredMime := file.Header.Get("Content-Type")
	if !validateMimeType(fileContent, declaredMime) {
		return c.JSON(400, map[string]string{"error": "File type not allowed"})
	}

	fileID := uuid.New().String()
	filePath, err := validateFilePath(app.Config.DataDir, fileID)
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid file path"})
	}

	os.MkdirAll(filepath.Dir(filePath), 0700)
	dst, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to create file"})
	}
	defer dst.Close()

	if _, err = dst.Write(fileContent); err != nil {
		os.Remove(filePath)
		return c.JSON(500, map[string]string{"error": "Failed to save file"})
	}

	token := generateSecureToken(32)
	detectedMime := http.DetectContentType(fileContent)
	fileRecord := File{
		ID:              fileID,
		Token:           token,
		Filename:        sanitizedFilename,
		Size:            file.Size,
		MimeType:        detectedMime,
		PersonalTokenID: personalTokenID,
		CreatedAt:       time.Now(),
	}

	if err := app.DB.Create(&fileRecord).Error; err != nil {
		os.Remove(filePath)
		return c.JSON(500, map[string]string{"error": "Failed to save file record"})
	}

	app.cleanupOldFiles()

	return c.JSON(200, map[string]interface{}{
		"id":       fileID,
		"token":    token,
		"filename": sanitizedFilename,
		"size":     file.Size,
		"url":      "/files/" + fileID,
	})
}

func (app *App) handleDownload(c echo.Context) error {
	fileID := c.Param("id")

	if len(fileID) > 100 {
		return c.JSON(400, map[string]string{"error": "Invalid file ID"})
	}

	var file File
	if err := app.DB.Where("id = ?", fileID).First(&file).Error; err != nil {
		return c.JSON(404, map[string]string{"error": "File not found"})
	}

	filePath, err := validateFilePath(app.Config.DataDir, fileID)
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid file path"})
	}

	return c.File(filePath)
}

func (app *App) handleDelete(c echo.Context) error {
	fileID := c.Param("id")

	if len(fileID) > 100 {
		return c.JSON(400, map[string]string{"error": "Invalid file ID"})
	}

	var file File
	if err := app.DB.Where("id = ?", fileID).First(&file).Error; err != nil {
		return c.JSON(404, map[string]string{"error": "File not found"})
	}

	filePath, err := validateFilePath(app.Config.DataDir, fileID)
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid file path"})
	}

	os.Remove(filePath)
	app.DB.Delete(&file)
	return c.JSON(200, map[string]string{"message": "File deleted"})
}

func (app *App) handleCreateToken(c echo.Context) error {
	var req struct {
		Key string `json:"key"`
	}

	if err := c.Bind(&req); err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid request"})
	}

	if len(req.Key) > 200 {
		return c.JSON(400, map[string]string{"error": "Invalid key"})
	}

	if req.Key != app.Config.MasterKey {
		return c.JSON(401, map[string]string{"error": "Invalid key"})
	}

	clientIP := c.RealIP()
	if len(clientIP) > 45 {
		clientIP = "unknown"
	}

	token := generateSecureToken(32)

	personalToken := PersonalToken{
		ID:        uuid.New().String(),
		Token:     token,
		IP:        clientIP,
		CreatedAt: time.Now(),
	}

	if err := app.DB.Create(&personalToken).Error; err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to create token"})
	}

	return c.JSON(200, map[string]string{"token": token})
}

func (app *App) rateLimitMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !app.RateLimiter.Allow() {
				return c.JSON(429, map[string]string{"error": "Rate limit exceeded"})
			}
			return next(c)
		}
	}
}

func (app *App) authRateLimitMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !app.AuthLimiter.Allow() {
				return c.JSON(429, map[string]string{"error": "Authentication rate limit exceeded"})
			}
			return next(c)
		}
	}
}

func (app *App) csrfMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().Method == "POST" || c.Request().Method == "PUT" || c.Request().Method == "DELETE" {
				csrfToken := c.Request().Header.Get("X-CSRF-Token")
				if csrfToken == "" {
					return c.JSON(403, map[string]string{"error": "CSRF token required"})
				}

				app.CSRFMutex.RLock()
				_, exists := app.CSRFTokens[csrfToken]
				app.CSRFMutex.RUnlock()

				if !exists {
					return c.JSON(403, map[string]string{"error": "Invalid CSRF token"})
				}
			}
			return next(c)
		}
	}
}

func (app *App) authMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		auth := c.Request().Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			return c.JSON(401, map[string]string{"error": "Missing or invalid authorization"})
		}

		tokenString := strings.TrimPrefix(auth, "Bearer ")
		token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(app.Config.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			return c.JSON(401, map[string]string{"error": "Invalid token"})
		}

		return next(c)
	}
}
