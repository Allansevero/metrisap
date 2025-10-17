package repository

import (
	"database/sql"
	"errors"
	"log"

	"github.com/google/uuid" // Import para geração de UUID
	"github.com/jmoiron/sqlx"
)

// PostgresRepository é a implementação do repositório para PostgreSQL.
type PostgresRepository struct {
	db *sqlx.DB
}

// NewPostgresRepository cria uma nova instância do PostgresRepository.
func NewPostgresRepository(db *sqlx.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// GetInstance busca uma única instância pelo seu ID, mas somente se ela pertencer ao supabase_user_id fornecido.
func (r *PostgresRepository) GetInstance(instanceID int, supabaseUserID string) (Instance, error) {
	var instance Instance
	query := "SELECT * FROM users WHERE id = $1 AND supabase_user_id = $2"
	err := r.db.Get(&instance, query, instanceID, supabaseUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return Instance{}, errors.New("instância não encontrada ou não pertence ao usuário")
		}
		log.Printf("Erro ao buscar instância %d para o usuário %s: %v", instanceID, supabaseUserID, err)
		return Instance{}, err
	}
	return instance, nil
}

// GetInstanceQRCode busca o qrcode de uma instância específica, validando a posse.
func (r *PostgresRepository) GetInstanceQRCode(instanceID int, supabaseUserID string) (string, error) {
	var qrCode string
	query := "SELECT qrcode FROM users WHERE id = $1 AND supabase_user_id = $2"
	err := r.db.Get(&qrCode, query, instanceID, supabaseUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.New("instância não encontrada ou não pertence ao usuário")
		}
		log.Printf("Erro ao buscar qrcode da instância %d para o usuário %s: %v", instanceID, supabaseUserID, err)
		return "", err
	}
	return qrCode, nil
}

// GetInstancesBySupabaseID retorna todas as instâncias de WhatsApp associadas a um supabase_user_id.
func (r *PostgresRepository) GetInstancesBySupabaseID(supabaseUserID string) ([]Instance, error) {
	var instances []Instance
	query := "SELECT * FROM users WHERE supabase_user_id = $1"
	err := r.db.Select(&instances, query, supabaseUserID)
	if err != nil {
		log.Printf("Erro ao buscar instâncias por supabase_user_id (%s): %v", supabaseUserID, err)
		return nil, err
	}
	return instances, nil
}

// AddInstance cria uma nova instância de WhatsApp no banco de dados, associada a um usuário do Supabase.
func (r *PostgresRepository) AddInstance(name, supabaseUserID string) (Instance, error) {
	newInstanceToken := uuid.New().String()
	var newInstance Instance
	query := `
		INSERT INTO users (name, token, supabase_user_id)
		VALUES ($1, $2, $3)
		RETURNING id, name, token, webhook, jid, qrcode, connected, expiration, events, supabase_user_id
	`
	err := r.db.Get(&newInstance, query, name, newInstanceToken, supabaseUserID)
	if err != nil {
		log.Printf("Erro ao criar nova instância para supabase_user_id (%s): %v", supabaseUserID, err)
		return Instance{}, err
	}
	log.Printf("Nova instância '%s' (ID: %d) criada para o usuário %s", newInstance.Name, newInstance.ID, supabaseUserID)
	return newInstance, nil
}

// UpdateInstance atualiza os dados de uma instância (como nome e webhook).
// A operação é segura, pois verifica a posse da instância.
func (r *PostgresRepository) UpdateInstance(instanceID int, supabaseUserID string, newName string, newWebhook string) (Instance, error) {
	var updatedInstance Instance
	query := `
		UPDATE users
		SET name = $1, webhook = $2
		WHERE id = $3 AND supabase_user_id = $4
		RETURNING id, name, token, webhook, jid, qrcode, connected, expiration, events, supabase_user_id
	`
	err := r.db.Get(&updatedInstance, query, newName, newWebhook, instanceID, supabaseUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return Instance{}, errors.New("instância não encontrada ou não pertence ao usuário")
		}
		log.Printf("Erro ao atualizar instância %d para o usuário %s: %v", instanceID, supabaseUserID, err)
		return Instance{}, err
	}
	return updatedInstance, nil
}

// DeleteInstance remove uma instância do banco de dados.
func (r *PostgresRepository) DeleteInstance(instanceID int, supabaseUserID string) error {
	result, err := r.db.Exec("DELETE FROM users WHERE id = $1 AND supabase_user_id = $2", instanceID, supabaseUserID)
	if err != nil {
		log.Printf("Erro ao deletar instância %d para o usuário %s: %v", instanceID, supabaseUserID, err)
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("instância não encontrada ou não pertence ao usuário")
	}
	log.Printf("Instância %d deletada com sucesso pelo usuário %s", instanceID, supabaseUserID)
	return nil
}

// ClearInstanceEvents limpa as configurações de eventos de uma instância no banco de dados.
func (r *PostgresRepository) ClearInstanceEvents(instanceID int, supabaseUserID string) error {
	query := "UPDATE users SET events='' WHERE id=$1 AND supabase_user_id=$2"
	result, err := r.db.Exec(query, instanceID, supabaseUserID)
	if err != nil {
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	log.Printf("%d linhas afetadas ao limpar eventos da instância %d", rowsAffected, instanceID)
	return nil
}

// Instance representa a estrutura de dados de uma instância do WhatsApp (uma linha na tabela 'users').
type Instance struct {
	ID             int    `db:"id"`
	Name           string `db:"name"`
	Token          string `db:"token"`
	Webhook        string `db:"webhook"`
	Jid            string `db:"jid"`
	Qrcode         string `db:"qrcode"`
	Connected      int    `db:"connected"`
	Expiration     int    `db:"expiration"`
	Events         string `db:"events"`
	SupabaseUserID string `db:"supabase_user_id"`
}