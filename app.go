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

//go:embed public/* mkbox.ico
var publicFiles embed.FS

// emebed fs my beloved

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

type App struct {
	DB            *gorm.DB
	Config        *Config
	RateLimiter   *rate.Limiter
	AuthLimiter   *rate.Limiter
	UploadLimiter *rate.Limiter
	CSRFTokens    map[string]time.Time
	CSRFMutex     sync.RWMutex
	FileCache     map[string]File
	CacheMutex    sync.RWMutex
	CleanupTicker *time.Ticker
	StatsCache    map[string]interface{}
	StatsMutex    sync.RWMutex
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
	JWTToken        string    `gorm:"uniqueIndex" json:"jwt_token"`
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
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
}

type Lockdown struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	Type      string    `json:"type"`  // "user" или "all"
	Token     string    `json:"token"` // для user типа
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

type Paste struct {
	ID        string     `gorm:"primaryKey" json:"id"`
	Content   string     `json:"content"`
	Syntax    string     `json:"syntax"`
	Once      bool       `json:"once"`
	Views     int        `json:"views"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type TokenClaims struct {
	FileID string `json:"file_id"`
	jwt.RegisteredClaims
}

type FileTokenClaims struct {
	FileID string `json:"file_id"`
	Type   string `json:"type"` // "file_access"
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
		SocketPath:     getEnv("MBOX_SOCKET_PATH", "/var/run/mkbox/mkbox.sock"),
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

	db.AutoMigrate(&File{}, &PersonalToken{}, &Lockdown{}, &Paste{})

	app := &App{
		DB:            db,
		Config:        config,
		RateLimiter:   rate.NewLimiter(rate.Limit(10), 20),
		AuthLimiter:   rate.NewLimiter(rate.Limit(5), 10),
		UploadLimiter: rate.NewLimiter(rate.Limit(3), 5), // 3 загрузки в секунду, burst 5
		CSRFTokens:    make(map[string]time.Time),
		FileCache:     make(map[string]File),
		StatsCache:    make(map[string]interface{}),
		CleanupTicker: time.NewTicker(5 * time.Minute),
	}

	app.loadConfig()

	go app.cleanupCSRFTokens()
	go app.cleanupCache()
	go app.preloadStats()

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
	for range app.CleanupTicker.C {
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

func (app *App) cleanupCache() {
	for range app.CleanupTicker.C {
		app.CacheMutex.Lock()
		cutoff := time.Now().Add(-1 * time.Hour)
		for id, file := range app.FileCache {
			if file.CreatedAt.Before(cutoff) {
				delete(app.FileCache, id)
			}
		}
		app.CacheMutex.Unlock()
	}
}

func (app *App) preloadStats() {
	for range time.Tick(30 * time.Second) {
		app.updateStatsCache()
	}
}

func (app *App) updateStatsCache() {
	var count int64
	var totalSize int64

	if err := app.DB.Model(&File{}).Count(&count).Error; err != nil {
		return
	}

	if err := app.DB.Model(&File{}).Select("COALESCE(SUM(size), 0)").Scan(&totalSize).Error; err != nil {
		return
	}

	app.StatsMutex.Lock()
	app.StatsCache["file_count"] = count
	app.StatsCache["total_size"] = totalSize
	app.StatsCache["last_updated"] = time.Now()
	app.StatsMutex.Unlock()
}

func (app *App) getCachedFile(fileID string) (File, bool) {
	app.CacheMutex.RLock()
	defer app.CacheMutex.RUnlock()
	file, exists := app.FileCache[fileID]
	return file, exists
}

func (app *App) setCachedFile(file File) {
	app.CacheMutex.Lock()
	defer app.CacheMutex.Unlock()
	app.FileCache[file.ID] = file
}

func (app *App) getCachedStats() (map[string]interface{}, bool) {
	app.StatsMutex.RLock()
	defer app.StatsMutex.RUnlock()

	if lastUpdated, ok := app.StatsCache["last_updated"].(time.Time); ok {
		if time.Since(lastUpdated) < 30*time.Second {
			return app.StatsCache, true
		}
	}
	return nil, false
}

func (app *App) validateFileJWT(tokenString, fileID string) bool {
	token, err := jwt.ParseWithClaims(tokenString, &FileTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(app.Config.JWTSecret), nil
	})

	if err != nil || !token.Valid {
		return false
	}

	claims, ok := token.Claims.(*FileTokenClaims)
	if !ok {
		return false
	}

	if claims.Type != "file_access" || claims.FileID != fileID {
		return false
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return false
	}

	return true
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

	e.GET("/style.css", app.handleStatic("public/style.css"))
	e.GET("/background.js", app.handleStatic("public/background.js"))
	e.GET("/app.js", app.handleStatic("public/app.js"))
	e.GET("/end-portal-*.png", app.handlePNG)
	e.GET("/", app.handleIndex)
	e.GET("/mkbox.ico", app.handleFavicon)
	e.GET("/csrf-token", app.handleCSRFToken)
	e.POST("/auth", app.handleAuth, app.authRateLimitMiddleware(), app.csrfMiddleware())
	e.POST("/create-token", app.handleCreateToken, app.authRateLimitMiddleware(), app.csrfMiddleware())
	e.POST("/upload", app.handleUpload, app.authMiddleware, app.uploadRateLimitMiddleware(), app.csrfMiddleware())
	e.GET("/files/:id", app.handleDownload)
	e.DELETE("/files/:id", app.handleDelete, app.authMiddleware, app.csrfMiddleware())
	e.GET("/api/files", app.handleListFiles, app.authMiddleware)
	e.GET("/api/stats", app.handleStats, app.authMiddleware)
	e.GET("/api/info", app.handleInfo)
	e.POST("/api/paste", app.handleCreatePaste, app.csrfMiddleware())
	e.GET("/p/:id", app.handlePasteView)
	e.GET("/p/:id/raw", app.handlePasteRaw)

	var listener net.Listener
	var err error

	if strings.HasPrefix(app.Config.SocketPath, ":") {
		listener, err = net.Listen("tcp", app.Config.SocketPath)
		log.Printf("mkboxd listening on %s", app.Config.SocketPath)
	} else {
		os.Remove(app.Config.SocketPath)
		listener, err = net.Listen("unix", app.Config.SocketPath)
		if err == nil {
			os.Chmod(app.Config.SocketPath, 0666)
		}
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

func (app *App) handleFavicon(c echo.Context) error {
	data, err := publicFiles.ReadFile("mkbox.ico")
	if err != nil {
		return c.String(404, "Not Found")
	}
	return c.Blob(200, "image/x-icon", data)
}

func (app *App) handleListFiles(c echo.Context) error {
	// жопа.
	auth := c.Request().Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return c.JSON(401, map[string]string{"error": "Missing authorization"})
	}

	tokenString := strings.TrimPrefix(auth, "Bearer ")
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(app.Config.JWTSecret), nil
	})

	if err != nil || !token.Valid {
		return c.JSON(401, map[string]string{"error": "Invalid token"})
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || claims.FileID != "" {
		return c.JSON(403, map[string]string{"error": "Admin access required"})
	}

	var files []File

	done := make(chan error, 1)
	go func() {
		done <- app.DB.Find(&files).Error
	}()

	select {
	case err := <-done:
		if err != nil {
			return c.JSON(500, map[string]string{"error": "Failed to list files"})
		}
	case <-time.After(5 * time.Second):
		return c.JSON(500, map[string]string{"error": "Request timeout"})
	}

	return c.JSON(200, files)
}

func (app *App) handleStats(c echo.Context) error {
	// чекаю, это мастер-ключ или не
	auth := c.Request().Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return c.JSON(401, map[string]string{"error": "Missing authorization"})
	}

	tokenString := strings.TrimPrefix(auth, "Bearer ")
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(app.Config.JWTSecret), nil
	})

	if err != nil || !token.Valid {
		return c.JSON(401, map[string]string{"error": "Invalid token"})
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || claims.FileID != "" {
		return c.JSON(403, map[string]string{"error": "Admin access required"})
	}

	if stats, ok := app.getCachedStats(); ok {
		return c.JSON(200, map[string]interface{}{
			"file_count": stats["file_count"],
			"total_size": stats["total_size"],
		})
	}

	app.updateStatsCache()

	if stats, ok := app.getCachedStats(); ok {
		return c.JSON(200, map[string]interface{}{
			"file_count": stats["file_count"],
			"total_size": stats["total_size"],
		})
	}

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
	clientIP := c.RealIP()
	userAgent := c.Request().Header.Get("User-Agent")

	lockdownChan := make(chan error, 1)
	go func() {
		var globalLockdown Lockdown
		lockdownChan <- app.DB.Where("type = ?", "all").First(&globalLockdown).Error
	}()

	select {
	case err := <-lockdownChan:
		if err == nil {
			log.Printf("SECURITY: Upload blocked due to global lockdown from %s (%s)", clientIP, userAgent)
			return c.JSON(403, map[string]string{"error": "Uploads are disabled"})
		}
	case <-time.After(2 * time.Second):
		log.Printf("SECURITY: Database timeout during upload from %s", clientIP)
		return c.JSON(500, map[string]string{"error": "Database timeout"})
	}

	personalToken := c.Request().Header.Get("X-Personal-Token")
	var personalTokenRecord PersonalToken
	var personalTokenID string

	if personalToken != "" {
		if len(personalToken) > 100 {
			return c.JSON(400, map[string]string{"error": "Invalid personal token"})
		}

		userLockdownChan := make(chan error, 1)
		go func() {
			var userLockdown Lockdown
			userLockdownChan <- app.DB.Where("type = ? AND token = ?", "user", personalToken).First(&userLockdown).Error
		}()

		select {
		case err := <-userLockdownChan:
			if err == nil {
				return c.JSON(403, map[string]string{"error": "User uploads are disabled"})
			}
		case <-time.After(2 * time.Second):
			return c.JSON(500, map[string]string{"error": "Database timeout"})
		}

		tokenChan := make(chan error, 1)
		go func() {
			tokenChan <- app.DB.Where("token = ?", personalToken).First(&personalTokenRecord).Error
		}()

		select {
		case err := <-tokenChan:
			if err != nil {
				return c.JSON(401, map[string]string{"error": "Invalid personal token"})
			}
			personalTokenID = personalTokenRecord.ID
		case <-time.After(2 * time.Second):
			return c.JSON(500, map[string]string{"error": "Database timeout"})
		}
	} else {
		tempToken := generateSecureToken(32)
		clientIP := c.RealIP()
		userAgent := c.Request().Header.Get("User-Agent")
		if len(userAgent) > 200 {
			userAgent = userAgent[:200]
		}

		personalTokenRecord = PersonalToken{
			ID:        uuid.New().String(),
			Token:     tempToken,
			IP:        clientIP,
			UserAgent: userAgent,
			CreatedAt: time.Now(),
		}

		tokenCreateChan := make(chan error, 1)
		go func() {
			tokenCreateChan <- app.DB.Create(&personalTokenRecord).Error
		}()

		select {
		case err := <-tokenCreateChan:
			if err != nil {
				return c.JSON(500, map[string]string{"error": "Failed to create temporary token"})
			}
			personalTokenID = personalTokenRecord.ID
		case <-time.After(3 * time.Second):
			return c.JSON(500, map[string]string{"error": "Database timeout"})
		}
	}

	file, err := c.FormFile("file")
	if err != nil {
		return c.JSON(400, map[string]string{"error": "No file provided"})
	}

	if file.Size > app.Config.MaxFileSize {
		log.Printf("SECURITY: File too large (%d bytes) from %s, filename: %s", file.Size, clientIP, file.Filename)
		return c.JSON(400, map[string]string{"error": "File too large"})
	}

	if file.Size <= 0 {
		log.Printf("SECURITY: Empty file upload attempt from %s, filename: %s", clientIP, file.Filename)
		return c.JSON(400, map[string]string{"error": "Empty file not allowed"})
	}

	var totalSize int64
	storageChan := make(chan error, 1)
	go func() {
		storageChan <- app.DB.Model(&File{}).Select("COALESCE(SUM(size), 0)").Scan(&totalSize).Error
	}()

	select {
	case err := <-storageChan:
		if err != nil {
			log.Printf("SECURITY: Failed to check storage size from %s: %v", clientIP, err)
			return c.JSON(500, map[string]string{"error": "Storage check failed"})
		}
		if totalSize+file.Size > app.Config.MaxStorageSize {
			log.Printf("SECURITY: Storage limit exceeded (%d + %d > %d) from %s", totalSize, file.Size, app.Config.MaxStorageSize, clientIP)
			return c.JSON(413, map[string]string{"error": "Storage limit exceeded"})
		}
	case <-time.After(2 * time.Second):
		log.Printf("SECURITY: Storage check timeout from %s", clientIP)
		return c.JSON(500, map[string]string{"error": "Storage check timeout"})
	}

	sanitizedFilename := sanitizeFilename(file.Filename)
	if sanitizedFilename == "" {
		log.Printf("SECURITY: Invalid filename from %s: %s", clientIP, file.Filename)
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
		log.Printf("SECURITY: Invalid MIME type from %s: declared=%s, filename=%s", clientIP, declaredMime, sanitizedFilename)
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

	// жвт для ФАЙЛОВ
	fileJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, FileTokenClaims{
		FileID: fileID,
		Type:   "file_access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)), // 7 дней
		},
	})
	fileJWTString, err := fileJWT.SignedString([]byte(app.Config.JWTSecret))
	if err != nil {
		os.Remove(filePath)
		return c.JSON(500, map[string]string{"error": "Failed to create file JWT token"})
	}

	detectedMime := http.DetectContentType(fileContent)
	fileRecord := File{
		ID:              fileID,
		Token:           token,
		JWTToken:        fileJWTString,
		Filename:        sanitizedFilename,
		Size:            file.Size,
		MimeType:        detectedMime,
		PersonalTokenID: personalTokenID,
		CreatedAt:       time.Now(),
	}

	dbSaveChan := make(chan error, 1)
	go func() {
		dbSaveChan <- app.DB.Create(&fileRecord).Error
	}()

	select {
	case err := <-dbSaveChan:
		if err != nil {
			os.Remove(filePath)
			return c.JSON(500, map[string]string{"error": "Failed to save file record"})
		}
	case <-time.After(5 * time.Second):
		os.Remove(filePath)
		return c.JSON(500, map[string]string{"error": "Database timeout"})
	}

	app.setCachedFile(fileRecord)

	go app.cleanupOldFiles()

	log.Printf("INFO: File uploaded successfully: ID=%s, filename=%s, size=%d, from=%s", fileID, sanitizedFilename, file.Size, clientIP)

	return c.JSON(200, map[string]interface{}{
		"id":        fileID,
		"token":     token,
		"jwt_token": fileJWTString,
		"filename":  sanitizedFilename,
		"size":      file.Size,
		"url":       "/files/" + fileID,
	})
}

func (app *App) handleDownload(c echo.Context) error {
	fileID := c.Param("id")

	if len(fileID) > 100 {
		return c.JSON(400, map[string]string{"error": "Invalid file ID"})
	}

	jwtToken := c.Request().Header.Get("X-File-Token")
	if jwtToken == "" {
		jwtToken = c.QueryParam("token")
	}

	var file File
	var found bool
	if cachedFile, ok := app.getCachedFile(fileID); ok {
		file = cachedFile
		found = true
	} else {
		if err := app.DB.Where("id = ?", fileID).First(&file).Error; err != nil {
			return c.JSON(404, map[string]string{"error": "File not found"})
		}
		found = true
		app.setCachedFile(file)
	}

	if !found {
		return c.JSON(404, map[string]string{"error": "File not found"})
	}

	if jwtToken != "" {
		if !app.validateFileJWT(jwtToken, fileID) {
			return c.JSON(403, map[string]string{"error": "Invalid file token"})
		}
	} else {
		regularToken := c.QueryParam("token")
		if regularToken == "" || regularToken != file.Token {
			return c.JSON(403, map[string]string{"error": "File token required"})
		}
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

	app.DB.Delete(&file)

	app.CacheMutex.Lock()
	delete(app.FileCache, fileID)
	app.CacheMutex.Unlock()

	go func() {
		os.Remove(filePath)
	}()

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

	userAgent := c.Request().Header.Get("User-Agent")
	if len(userAgent) > 200 {
		userAgent = userAgent[:200]
	}

	token := generateSecureToken(32)

	personalToken := PersonalToken{
		ID:        uuid.New().String(),
		Token:     token,
		IP:        clientIP,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
	}

	tokenCreateChan := make(chan error, 1)
	go func() {
		tokenCreateChan <- app.DB.Create(&personalToken).Error
	}()

	select {
	case err := <-tokenCreateChan:
		if err != nil {
			return c.JSON(500, map[string]string{"error": "Failed to create token"})
		}
	case <-time.After(3 * time.Second):
		return c.JSON(500, map[string]string{"error": "Database timeout"})
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
				log.Printf("SECURITY: Auth rate limit exceeded from %s", c.RealIP())
				return c.JSON(429, map[string]string{"error": "Authentication rate limit exceeded"})
			}
			return next(c)
		}
	}
}

func (app *App) uploadRateLimitMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !app.UploadLimiter.Allow() {
				log.Printf("SECURITY: Upload rate limit exceeded from %s", c.RealIP())
				return c.JSON(429, map[string]string{"error": "Upload rate limit exceeded"})
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

				app.CSRFMutex.Lock()
				_, exists := app.CSRFTokens[csrfToken]
				if exists {
					delete(app.CSRFTokens, csrfToken)
				}
				app.CSRFMutex.Unlock()

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

		if err != nil {
			log.Printf("JWT parse error: %v", err)
			return c.JSON(401, map[string]string{"error": "Invalid token"})
		}

		if !token.Valid {
			return c.JSON(401, map[string]string{"error": "Invalid token"})
		}

		claims, ok := token.Claims.(*TokenClaims)
		if !ok {
			return c.JSON(401, map[string]string{"error": "Invalid token claims"})
		}

		if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
			return c.JSON(401, map[string]string{"error": "Token expired"})
		}

		return next(c)
	}
}

func (app *App) handleInfo(c echo.Context) error {
	return c.JSON(200, map[string]string{
		"version": "mkbox-a1.1",
	})
}

const base62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func generateBase62(n int) string {
	b := make([]byte, n)
	for i := range b {
		r := make([]byte, 1)
		_, err := rand.Read(r)
		if err != nil {
			b[i] = base62[int(time.Now().UnixNano())%len(base62)]
		} else {
			b[i] = base62[int(r[0])%len(base62)]
		}
	}
	return string(b)
}

func (app *App) handleCreatePaste(c echo.Context) error {
	var req struct {
		Content string `json:"content"`
		Syntax  string `json:"syntax"`
		TTL     int    `json:"ttl_sec"`
		Once    bool   `json:"once"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid request"})
	}
	if len(req.Content) == 0 {
		return c.JSON(400, map[string]string{"error": "Empty content"})
	}
	if len(req.Content) > 1_000_000 {
		return c.JSON(413, map[string]string{"error": "Content too large"})
	}
	id := generateBase62(8)
	var expires *time.Time
	if req.TTL > 0 {
		t := time.Now().Add(time.Duration(req.TTL) * time.Second)
		expires = &t
	}
	p := Paste{
		ID:        id,
		Content:   req.Content,
		Syntax:    req.Syntax,
		Once:      req.Once,
		Views:     0,
		CreatedAt: time.Now(),
		ExpiresAt: expires,
	}
	if err := app.DB.Create(&p).Error; err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to save paste"})
	}
	return c.JSON(200, map[string]string{
		"id":      id,
		"url":     "/p/" + id,
		"raw_url": "/p/" + id + "/raw",
	})
}

func (app *App) handlePasteRaw(c echo.Context) error {
	id := c.Param("id")
	var p Paste
	if err := app.DB.Where("id = ?", id).First(&p).Error; err != nil {
		return c.String(404, "Not Found")
	}
	if p.ExpiresAt != nil && time.Now().After(*p.ExpiresAt) {
		app.DB.Delete(&p)
		return c.String(404, "Not Found")
	}
	if p.Once {
		app.DB.Delete(&p)
	} else {
		app.DB.Model(&p).UpdateColumn("views", gorm.Expr("views + 1"))
	}
	return c.Blob(200, "text/plain; charset=utf-8", []byte(p.Content))
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return r.Replace(s)
}

// КОСТЫЫЫЛЬ
func (app *App) handlePasteView(c echo.Context) error {
	id := c.Param("id")
	var p Paste
	if err := app.DB.Where("id = ?", id).First(&p).Error; err != nil {
		return c.String(404, "Not Found")
	}
	if p.ExpiresAt != nil && time.Now().After(*p.ExpiresAt) {
		app.DB.Delete(&p)
		return c.String(404, "Not Found")
	}
	esc := htmlEscape(p.Content)
	if p.Once {
		app.DB.Delete(&p)
	} else {
		app.DB.Model(&p).UpdateColumn("views", gorm.Expr("views + 1"))
	}
	html := "<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, viewport-fit=cover\"><base href=\"/\"><title>paste " + id + "</title>" +
		"<link rel=\"stylesheet\" href=\"/style.css\">" +
		"<script type=\"importmap\">{\n  \"imports\": {\n    \"three\": \"https://unpkg.com/three@0.160.0/build/three.module.js\"\n  }\n}</script>" +
		"<style>pre{white-space:pre-wrap;word-wrap:break-word;border:1px solid var(--accent);padding:1em;background:rgba(0,0,0,0.3);backdrop-filter:blur(10px);overflow:auto}</style>" +
		"</head><body>" +
		"<div id=\"background\"></div><div id=\"content\">" +
		"<div class=\"header-nav\"><a class=\"logo\" href=\"/\">mkbox</a></div>" +
		"<div class=\"status-section\"><a href=\"/p/" + id + "/raw\">raw</a></div>" +
		"<pre>" + esc + "</pre>" +
		"</div>" +
		"<script type=\"module\">import background from '/background.js';background(document.getElementById('background'));</script>" +
		"</body></html>"
	return c.HTML(200, html)
}
