package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Ctl struct {
	SocketPath string
	DataDir    string
}

func NewCtl() *Ctl {
	return &Ctl{
		SocketPath: getEnv("MBOX_SOCKET_PATH", "/var/run/mkbox.sock"),
		DataDir:    getEnv("MBOX_DATA_DIR", "/var/lib/mkbox"),
	}
}

func (ctl *Ctl) Run() {
	if len(os.Args) < 3 {
		ctl.showHelp()
		return
	}

	command := os.Args[2]
	switch command {
	case "init":
		ctl.init()
	case "list":
		ctl.listFiles()
	case "info":
		if len(os.Args) < 4 {
			fmt.Println("Usage: mkboxctl info <file_id>")
			return
		}
		ctl.fileInfo(os.Args[3])
	case "reset-token":
		if len(os.Args) < 4 {
			fmt.Println("Usage: mkboxctl reset-token <file_id>")
			return
		}
		ctl.resetToken(os.Args[3])
	case "delete":
		if len(os.Args) < 4 {
			fmt.Println("Usage: mkboxctl delete <file_id>")
			return
		}
		ctl.deleteFile(os.Args[3])
	case "config":
		ctl.showConfig()
	case "set-max-size":
		if len(os.Args) < 4 {
			fmt.Println("Usage: mkboxctl set-max-size <size_in_bytes>")
			return
		}
		size, err := strconv.ParseInt(os.Args[3], 10, 64)
		if err != nil {
			fmt.Printf("Invalid size: %v\n", err)
			return
		}
		ctl.setMaxSize(size)
	case "set-max-storage":
		if len(os.Args) < 4 {
			fmt.Println("Usage: mkboxctl set-max-storage <size_in_bytes>")
			return
		}
		size, err := strconv.ParseInt(os.Args[3], 10, 64)
		if err != nil {
			fmt.Printf("Invalid size: %v\n", err)
			return
		}
		ctl.setMaxStorage(size)
	case "delete-all":
		if len(os.Args) < 4 {
			fmt.Println("Usage: mkboxctl delete-all <personal_token>")
			return
		}
		ctl.deleteAllFiles(os.Args[3])
	case "lockdown-user":
		if len(os.Args) < 4 {
			fmt.Println("Usage: mkboxctl lockdown-user <personal_token> [-m message]")
			return
		}
		message := ""
		if len(os.Args) > 4 && os.Args[4] == "-m" && len(os.Args) > 5 {
			message = os.Args[5]
		}
		ctl.lockdownUser(os.Args[3], message)
	case "lockdown-all":
		message := ""
		if len(os.Args) > 3 && os.Args[3] == "-m" && len(os.Args) > 4 {
			message = os.Args[4]
		}
		ctl.lockdownAll(message)
	case "unlock-user":
		if len(os.Args) < 4 {
			fmt.Println("Usage: mkboxctl unlock-user <personal_token>")
			return
		}
		ctl.unlockUser(os.Args[3])
	case "unlock-all":
		ctl.unlockAll()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		ctl.showHelp()
	}
}

func (ctl *Ctl) showHelp() {
	fmt.Println("mkboxctl - управление mkbox сервером")
	fmt.Println()
	fmt.Println("Команды:")
	fmt.Println("  init                    - инициализация сервера")
	fmt.Println("  list                    - список всех файлов")
	fmt.Println("  info <file_id>          - информация о файле")
	fmt.Println("  reset-token <file_id>   - сброс токена файла")
	fmt.Println("  delete <file_id>        - удаление файла")
	fmt.Println("  delete-all <token>      - удалить все файлы по персональному токену")
	fmt.Println("  lockdown-user <token> [-m message] - заблокировать пользователя")
	fmt.Println("  lockdown-all [-m message]          - заблокировать все загрузки")
	fmt.Println("  unlock-user <token>     - разблокировать пользователя")
	fmt.Println("  unlock-all              - разблокировать все загрузки")
	fmt.Println("  config                  - показать конфигурацию")
	fmt.Println("  set-max-size <size>     - установить максимальный размер файла")
	fmt.Println("  set-max-storage <size>  - установить максимальный размер хранилища")
}

func (ctl *Ctl) init() {
	fmt.Println("Инициализация mkbox...")

	os.MkdirAll(ctl.DataDir, 0755)
	os.MkdirAll(filepath.Join(ctl.DataDir, "files"), 0755)
	os.MkdirAll(filepath.Dir(ctl.SocketPath), 0755)

	configPath := filepath.Join(ctl.DataDir, "config")
	if _, err := os.Stat(configPath); err == nil {
		fmt.Println("Конфигурация уже существует")
		return
	}

	key := generateRandomString(32)
	secret := generateRandomString(32)

	config := fmt.Sprintf("MASTER_KEY=%s\nJWT_SECRET=%s\nMAX_FILE_SIZE=104857600\nMAX_STORAGE_SIZE=1073741824\n", key, secret)

	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		fmt.Printf("Ошибка создания конфигурации: %v\n", err)
		return
	}

	fmt.Printf("Ключ доступа: %s\n", key)
	fmt.Println("Сохраните этот ключ в безопасном месте!")
	fmt.Println("Инициализация завершена")
}

func (ctl *Ctl) listFiles() {
	dbPath := filepath.Join(ctl.DataDir, "db.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		fmt.Println("База данных не найдена. Запустите 'mkboxctl init'")
		return
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Printf("Ошибка подключения к базе данных: %v\n", err)
		return
	}
	defer db.Close()

	fmt.Println("Файлы:")
	fmt.Printf("%-36s %-20s %-10s %-20s\n", "ID", "Имя файла", "Размер", "Создан")
	fmt.Println(strings.Repeat("-", 90))

	rows, err := db.Query("SELECT id, filename, size, created_at FROM files ORDER BY created_at DESC")
	if err != nil {
		fmt.Printf("Ошибка получения списка файлов: %v\n", err)
		return
	}
	defer rows.Close()

	fileCount := 0
	for rows.Next() {
		var id, filename string
		var size int64
		var createdAt time.Time

		if err := rows.Scan(&id, &filename, &size, &createdAt); err != nil {
			fmt.Printf("Ошибка чтения данных файла: %v\n", err)
			continue
		}

		sizeStr := formatSize(size)
		createdStr := createdAt.Format("2006-01-02 15:04:05")

		if len(filename) > 20 {
			filename = filename[:17] + "..."
		}

		fmt.Printf("%-36s %-20s %-10s %-20s\n", id, filename, sizeStr, createdStr)
		fileCount++
	}

	if fileCount == 0 {
		fmt.Println("Файлы не найдены")
	}
}

func (ctl *Ctl) fileInfo(fileID string) {
	dbPath := filepath.Join(ctl.DataDir, "db.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		fmt.Println("База данных не найдена. Запустите 'mkboxctl init'")
		return
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Printf("Ошибка подключения к базе данных: %v\n", err)
		return
	}
	defer db.Close()

	var file File
	var personalTokenID sql.NullString
	err = db.QueryRow("SELECT id, token, filename, size, mime_type, personal_token_id, created_at FROM files WHERE id = ?", fileID).Scan(
		&file.ID, &file.Token, &file.Filename, &file.Size, &file.MimeType, &personalTokenID, &file.CreatedAt)

	if personalTokenID.Valid {
		file.PersonalTokenID = personalTokenID.String
	}
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("Файл с ID %s не найден\n", fileID)
		} else {
			fmt.Printf("Ошибка получения информации о файле: %v\n", err)
		}
		return
	}

	filePath := filepath.Join(ctl.DataDir, "files", fileID)
	fileExists := true
	if _, err := os.Stat(filePath); err != nil {
		fileExists = false
	}

	var personalToken string
	if file.PersonalTokenID != "" {
		db.QueryRow("SELECT token FROM personal_tokens WHERE id = ?", file.PersonalTokenID).Scan(&personalToken)
	}

	fmt.Printf("Информация о файле %s:\n", fileID)
	fmt.Printf("  ID: %s\n", file.ID)
	fmt.Printf("  Токен: %s\n", file.Token)
	fmt.Printf("  Имя файла: %s\n", file.Filename)
	fmt.Printf("  Размер: %s\n", formatSize(file.Size))
	fmt.Printf("  MIME-тип: %s\n", file.MimeType)
	fmt.Printf("  Персональный токен: %s\n", personalToken)
	fmt.Printf("  Создан: %s\n", file.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Файл на диске: %t\n", fileExists)
	fmt.Printf("  URL: /files/%s\n", file.ID)
}

func (ctl *Ctl) resetToken(fileID string) {
	dbPath := filepath.Join(ctl.DataDir, "db.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		fmt.Println("База данных не найдена. Запустите 'mkboxctl init'")
		return
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Printf("Ошибка подключения к базе данных: %v\n", err)
		return
	}
	defer db.Close()

	var file File
	err = db.QueryRow("SELECT id, filename FROM files WHERE id = ?", fileID).Scan(&file.ID, &file.Filename)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("Файл с ID %s не найден\n", fileID)
		} else {
			fmt.Printf("Ошибка поиска файла: %v\n", err)
		}
		return
	}

	newToken := generateRandomString(32)
	_, err = db.Exec("UPDATE files SET token = ? WHERE id = ?", newToken, fileID)
	if err != nil {
		fmt.Printf("Ошибка обновления токена: %v\n", err)
		return
	}

	fmt.Printf("Токен для файла %s (%s) сброшен\n", fileID, file.Filename)
	fmt.Printf("Новый токен: %s\n", newToken)
}

func (ctl *Ctl) deleteFile(fileID string) {
	dbPath := filepath.Join(ctl.DataDir, "db.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		fmt.Println("База данных не найдена. Запустите 'mkboxctl init'")
		return
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Printf("Ошибка подключения к базе данных: %v\n", err)
		return
	}
	defer db.Close()

	var file File
	err = db.QueryRow("SELECT id, filename FROM files WHERE id = ?", fileID).Scan(&file.ID, &file.Filename)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("Файл с ID %s не найден\n", fileID)
		} else {
			fmt.Printf("Ошибка поиска файла: %v\n", err)
		}
		return
	}

	filePath := filepath.Join(ctl.DataDir, "files", fileID)
	if err := os.Remove(filePath); err != nil {
		fmt.Printf("Ошибка удаления файла с диска: %v\n", err)
	}

	_, err = db.Exec("DELETE FROM files WHERE id = ?", fileID)
	if err != nil {
		fmt.Printf("Ошибка удаления записи из базы данных: %v\n", err)
		return
	}

	fmt.Printf("Файл %s (%s) успешно удален\n", fileID, file.Filename)
}

func (ctl *Ctl) showConfig() {
	configPath := filepath.Join(ctl.DataDir, "config")
	if _, err := os.Stat(configPath); err != nil {
		fmt.Println("Конфигурация не найдена. Запустите 'mkboxctl init'")
		return
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Printf("Ошибка чтения конфигурации: %v\n", err)
		return
	}

	fmt.Println("Конфигурация:")
	fmt.Println(string(data))
}

func (ctl *Ctl) setMaxSize(size int64) {
	configPath := filepath.Join(ctl.DataDir, "config")
	if _, err := os.Stat(configPath); err != nil {
		fmt.Println("Конфигурация не найдена. Запустите 'mkboxctl init'")
		return
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Printf("Ошибка чтения конфигурации: %v\n", err)
		return
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "MAX_FILE_SIZE=") {
			lines[i] = fmt.Sprintf("MAX_FILE_SIZE=%d", size)
			break
		}
	}

	if err := os.WriteFile(configPath, []byte(strings.Join(lines, "\n")), 0600); err != nil {
		fmt.Printf("Ошибка сохранения конфигурации: %v\n", err)
		return
	}

	fmt.Printf("Максимальный размер файла установлен: %d байт\n", size)
}

func (ctl *Ctl) setMaxStorage(size int64) {
	configPath := filepath.Join(ctl.DataDir, "config")
	if _, err := os.Stat(configPath); err != nil {
		fmt.Println("Конфигурация не найдена. Запустите 'mkboxctl init'")
		return
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Printf("Ошибка чтения конфигурации: %v\n", err)
		return
	}

	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, "MAX_STORAGE_SIZE=") {
			lines[i] = fmt.Sprintf("MAX_STORAGE_SIZE=%d", size)
			found = true
			break
		}
	}

	if !found {
		lines = append(lines, fmt.Sprintf("MAX_STORAGE_SIZE=%d", size))
	}

	if err := os.WriteFile(configPath, []byte(strings.Join(lines, "\n")), 0600); err != nil {
		fmt.Printf("Ошибка сохранения конфигурации: %v\n", err)
		return
	}

	fmt.Printf("Максимальный размер хранилища установлен: %d байт\n", size)
}

func (ctl *Ctl) deleteAllFiles(personalToken string) {
	dbPath := filepath.Join(ctl.DataDir, "db.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		fmt.Println("База данных не найдена. Запустите 'mkboxctl init'")
		return
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Printf("Ошибка подключения к базе данных: %v\n", err)
		return
	}
	defer db.Close()

	var tokenID string
	err = db.QueryRow("SELECT id FROM personal_tokens WHERE token = ?", personalToken).Scan(&tokenID)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("Персональный токен не найден")
		} else {
			fmt.Printf("Ошибка проверки токена: %v\n", err)
		}
		return
	}

	var personalTokenID string
	err = db.QueryRow("SELECT id FROM personal_tokens WHERE token = ?", personalToken).Scan(&personalTokenID)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("Персональный токен не найден")
		} else {
			fmt.Printf("Ошибка проверки токена: %v\n", err)
		}
		return
	}

	rows, err := db.Query("SELECT id FROM files WHERE personal_token_id = ?", personalTokenID)
	if err != nil {
		fmt.Printf("Ошибка получения списка файлов: %v\n", err)
		return
	}
	defer rows.Close()

	var fileIDs []string
	for rows.Next() {
		var fileID string
		if err := rows.Scan(&fileID); err != nil {
			fmt.Printf("Ошибка чтения ID файла: %v\n", err)
			continue
		}
		fileIDs = append(fileIDs, fileID)
	}

	if len(fileIDs) == 0 {
		fmt.Println("Файлы пользователя не найдены")
		return
	}

	deletedCount := 0
	for _, fileID := range fileIDs {
		filePath := filepath.Join(ctl.DataDir, "files", fileID)
		if err := os.Remove(filePath); err != nil {
			fmt.Printf("Ошибка удаления файла %s: %v\n", fileID, err)
		} else {
			deletedCount++
		}
	}

	_, err = db.Exec("DELETE FROM files WHERE personal_token_id = ?", personalTokenID)
	if err != nil {
		fmt.Printf("Ошибка удаления записей из базы данных: %v\n", err)
		return
	}

	fmt.Printf("Удалено %d файлов по персональному токену\n", deletedCount)
}

func formatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}

func (ctl *Ctl) lockdownUser(personalToken, message string) {
	dbPath := filepath.Join(ctl.DataDir, "db.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		fmt.Println("База данных не найдена. Запустите 'mkboxctl init'")
		return
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Printf("Ошибка подключения к базе данных: %v\n", err)
		return
	}
	defer db.Close()

	var personalTokenRecord PersonalToken
	err = db.QueryRow("SELECT id, token FROM personal_tokens WHERE token = ?", personalToken).Scan(&personalTokenRecord.ID, &personalTokenRecord.Token)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("Персональный токен %s не найден\n", personalToken)
		} else {
			fmt.Printf("Ошибка поиска токена: %v\n", err)
		}
		return
	}

	db.Exec("DELETE FROM lockdowns WHERE type = ? AND token = ?", "user", personalToken)

	lockdownID := generateRandomString(16)
	_, err = db.Exec("INSERT INTO lockdowns (id, type, token, message, created_at) VALUES (?, ?, ?, ?, ?)",
		lockdownID, "user", personalToken, message, time.Now())
	if err != nil {
		fmt.Printf("Ошибка создания блокировки: %v\n", err)
		return
	}

	fmt.Printf("Пользователь с токеном %s заблокирован\n", personalToken)
	if message != "" {
		fmt.Printf("Сообщение: %s\n", message)
	}
}

func (ctl *Ctl) lockdownAll(message string) {
	dbPath := filepath.Join(ctl.DataDir, "db.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		fmt.Println("База данных не найдена. Запустите 'mkboxctl init'")
		return
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Printf("Ошибка подключения к базе данных: %v\n", err)
		return
	}
	defer db.Close()

	db.Exec("DELETE FROM lockdowns WHERE type = ?", "all")

	lockdownID := generateRandomString(16)
	_, err = db.Exec("INSERT INTO lockdowns (id, type, token, message, created_at) VALUES (?, ?, ?, ?, ?)",
		lockdownID, "all", "", message, time.Now())
	if err != nil {
		fmt.Printf("Ошибка создания блокировки: %v\n", err)
		return
	}

	fmt.Println("Все загрузки заблокированы")
	if message != "" {
		fmt.Printf("Сообщение: %s\n", message)
	}
}

func (ctl *Ctl) unlockUser(personalToken string) {
	dbPath := filepath.Join(ctl.DataDir, "db.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		fmt.Println("База данных не найдена. Запустите 'mkboxctl init'")
		return
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Printf("Ошибка подключения к базе данных: %v\n", err)
		return
	}
	defer db.Close()

	result, err := db.Exec("DELETE FROM lockdowns WHERE type = ? AND token = ?", "user", personalToken)
	if err != nil {
		fmt.Printf("Ошибка удаления блокировки: %v\n", err)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		fmt.Printf("Пользователь с токеном %s разблокирован\n", personalToken)
	} else {
		fmt.Printf("Блокировка для токена %s не найдена\n", personalToken)
	}
}

func (ctl *Ctl) unlockAll() {
	dbPath := filepath.Join(ctl.DataDir, "db.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		fmt.Println("База данных не найдена. Запустите 'mkboxctl init'")
		return
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Printf("Ошибка подключения к базе данных: %v\n", err)
		return
	}
	defer db.Close()

	result, err := db.Exec("DELETE FROM lockdowns WHERE type = ?", "all")
	if err != nil {
		fmt.Printf("Ошибка удаления блокировки: %v\n", err)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		fmt.Println("Все загрузки разблокированы")
	} else {
		fmt.Println("Глобальная блокировка не найдена")
	}
}
