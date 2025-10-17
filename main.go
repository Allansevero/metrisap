package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"go.mau.fi/whatsmeow/store/sqlstore"
	waLog "go.mau.fi/whatsmeow/util/log"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/patrickmn/go-cache"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type server struct {
	db     *sqlx.DB
	router *mux.Router
	exPath string
}

var (
	address     = flag.String("address", "0.0.0.0", "Bind IP Address")
	port        = flag.String("port", "8080", "Listen Port")
	waDebug     = flag.String("wadebug", "", "Enable whatsmeow debug (INFO or DEBUG)")
	logType     = flag.String("logtype", "console", "Type of log output (console or json)")
	colorOutput = flag.Bool("color", false, "Enable colored output for console logs")
	sslcert     = flag.String("sslcertificate", "", "SSL Certificate File")
	sslprivkey  = flag.String("sslprivatekey", "", "SSL Certificate Private Key File")
	adminToken  = flag.String("admintoken", "", "Security Token to authorize admin actions (list/create/remove users)")

	container     *sqlstore.Container
	killchannel   = make(map[int](chan bool))
	userinfocache = cache.New(5*time.Minute, 10*time.Minute)
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Warn().Err(err).Msg("Não foi possível carregar o arquivo .env (pode ser que não exista).")
	}

	flag.Parse()

	tz := os.Getenv("TZ")
	if tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			log.Warn().Err(err).Msgf("Não foi possível definir TZ=%q, usando UTC", tz)
		} else {
			time.Local = loc
			log.Info().Str("TZ", tz).Msg("Timezone definido pelo ambiente")
		}
	}

	if *logType == "json" {
		log.Logger = zerolog.New(os.Stdout).
			With().
			Timestamp().
			Str("role", filepath.Base(os.Args[0])).
			Logger()
	} else {
		output := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: "2006-01-02 15:04:05 -07:00",
			NoColor:    !*colorOutput,
		}

		output.FormatLevel = func(i interface{}) string {
			if i == nil {
				return ""
			}
			lvl := strings.ToUpper(i.(string))
			switch lvl {
			case "DEBUG":
				return "\x1b[34m" + lvl + "\x1b[0m"
			case "INFO":
				return "\x1b[32m" + lvl + "\x1b[0m"
			case "WARN":
				return "\x1b[33m" + lvl + "\x1b[0m"
			case "ERROR", "FATAL", "PANIC":
				return "\x1b[31m" + lvl + "\x1b[0m"
			default:
				return lvl
			}
		}

		log.Logger = zerolog.New(output).
			With().
			Timestamp().
			Str("role", filepath.Base(os.Args[0])).
			Logger()
	}

	if *adminToken == "" {
		if v := os.Getenv("WUZAPI_ADMIN_TOKEN"); v != "" {
			*adminToken = v
		}
	}
}

func main() {
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)

	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")

	dsn := fmt.Sprintf(
		"user=%s password=%s dbname=%s host=%s port=%s sslmode=disable",
		dbUser, dbPassword, dbName, dbHost, dbPort,
	)

	var db *sqlx.DB
	const maxAttempts = 10
	for i := 1; i <= maxAttempts; i++ {
		db, err = sqlx.Open("postgres", dsn)
		if err == nil {
			errPing := db.Ping()
			if errPing == nil {
				log.Info().Msgf("[DB] Conexão PostgreSQL estabelecida na tentativa %d", i)
				break
			}
			err = errPing
		}
		log.Warn().Msgf("[DB] Falha ao conectar (%d/%d): %v", i, maxAttempts, err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatal().Err(err).Msgf("[DB] Não foi possível conectar ao PostgreSQL após %d tentativas", maxAttempts)
		os.Exit(1)
	}

	if err := runMigrations(db, exPath); err != nil {
		log.Fatal().Err(err).Msg("Falha ao executar migrações")
		os.Exit(1)
	}

	var dbLog waLog.Logger
	if *waDebug != "" {
		dbLog = waLog.Stdout("Database", *waDebug, *colorOutput)
	}
	container, err = sqlstore.New(context.Background(), "postgres", dsn, dbLog)
	if err != nil {
		log.Fatal().Err(err).Msg("Falha ao criar container sqlstore")
		os.Exit(1)
	}

	s := &server{
		router: mux.NewRouter(),
		db:     db,
		exPath: exPath,
	}

	// Configuração do CORS
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "token", "instance-token"},
		AllowCredentials: true,
	})

	s.router.PathPrefix("/files/").Handler(http.StripPrefix("/files/", http.FileServer(http.Dir("./files"))))

	s.routes()

	s.connectOnStartup()

	srv := &http.Server{
		Addr:              *address + ":" + *port,
		Handler:           corsMiddleware.Handler(s.router), // Aplicando o middleware CORS
		ReadHeaderTimeout: 20 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       180 * time.Second,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if *sslcert != "" {
			if err := srv.ListenAndServeTLS(*sslcert, *sslprivkey); err != nil && err != http.ErrServerClosed {
				log.Fatal().Err(err).Msg("Falha ao iniciar o servidor HTTPS")
			}
		} else {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal().Err(err).Msg("Falha ao iniciar o servidor HTTP")
			}
		}
	}()
	log.Info().Str("address", *address).Str("port", *port).Msg("Servidor iniciado. Aguardando conexões...")

	<-done
	log.Warn().Msg("Servidor parando...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Falha ao parar o servidor")
		os.Exit(1)
	}
	log.Info().Msg("Servidor saiu corretamente")
}

func runMigrations(db *sqlx.DB, exPath string) error {
	log.Info().Msg("Iniciando processo de migração do banco de dados...")

	// 1. Create migrations table if it doesn't exist
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(255) PRIMARY KEY)`)
	if err != nil {
		return fmt.Errorf("falha ao criar tabela de migrações: %w", err)
	}
	log.Info().Msg("Tabela 'schema_migrations' verificada/criada.")

	// 2. Get executed migrations
	executed := make(map[string]bool)
	var versions []string
	err = db.Select(&versions, "SELECT version FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("falha ao buscar migrações executadas: %w", err)
	}
	for _, v := range versions {
		executed[v] = true
	}
	log.Info().Msgf("%d migrações já foram executadas.", len(executed))

	// 3. Find and apply new migrations
	migrationsDir := filepath.Join(exPath, "migrations")
	files, err := ioutil.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("falha ao ler diretório de migrações: %w", err)
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() < files[j].Name()
	})

	applied := 0
	for _, file := range files {
		fileName := file.Name()
		if strings.HasSuffix(fileName, ".up.sql") {
			if !executed[fileName] {
				log.Info().Msgf("Aplicando migração: %s", fileName)
				filePath := filepath.Join(migrationsDir, fileName)
				sqlBytes, err := ioutil.ReadFile(filePath)
				if err != nil {
					return fmt.Errorf("falha ao ler arquivo de migração %s: %w", fileName, err)
				}

				tx, err := db.Begin()
				if err != nil {
					return fmt.Errorf("falha ao iniciar transação para migração %s: %w", fileName, err)
				}

				if _, err := tx.Exec(string(sqlBytes)); err != nil {
					tx.Rollback()
					return fmt.Errorf("falha ao executar migração %s: %w", fileName, err)
				}

				if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES ($1)", fileName); err != nil {
					tx.Rollback()
					return fmt.Errorf("falha ao registrar migração %s: %w", fileName, err)
				}

				if err := tx.Commit(); err != nil {
					return fmt.Errorf("falha ao commitar transação para migração %s: %w", fileName, err)
				}

				log.Info().Msgf("Migração %s aplicada com sucesso.", fileName)
				applied++
			}
		}
	}

	if applied > 0 {
		log.Info().Msgf("Total de %d novas migrações aplicadas.", applied)
	} else {
		log.Info().Msg("Nenhuma nova migração para aplicar. O banco de dados está atualizado.")
	}

	// After migrations, check if we need to create the default admin user
	var userCount int
	err = db.Get(&userCount, "SELECT COUNT(*) FROM users")
	if err != nil {
		// This could happen if the first migration failed to create the users table
		log.Warn().Err(err).Msg("Não foi possível verificar a contagem de usuários. A tabela 'users' pode não existir ainda. Pulando a criação do usuário padrão.")
		return nil
	}

	if userCount == 0 {
		log.Warn().Msg("Nenhum usuário encontrado. Inserindo usuário padrão 'admin'.")
		userToken := *adminToken
		if userToken == "" {
			userToken = "1234ABCD" // Default value
			log.Warn().Msg("WUZAPI_ADMIN_TOKEN não definido, usando token padrão")
		}
		if _, err := db.Exec("INSERT INTO users (name, token) VALUES ($1, $2)", "admin", userToken); err != nil {
			if strings.Contains(err.Error(), "duplicate key") {
				log.Warn().Msg("Usuário padrão já existe. Ignorando.")
			} else {
				return fmt.Errorf("erro ao inserir usuário padrão: %w", err)
			}
		} else {
			log.Info().Msgf("Usuário padrão (admin/%s) inserido com sucesso.", userToken)
		}
	}

	return nil
}
