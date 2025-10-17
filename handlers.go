package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wuzapi/repository" // Adicionando a importação que faltava

	"github.com/gorilla/mux"
	"github.com/nfnt/resize"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"github.com/vincent-petithory/dataurl"
	"go.mau.fi/whatsmeow"
	waProto "go.mau.fi/whatsmeow/binary/proto"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"
)

type Values struct {
	m map[string]string
}

func (v Values) Get(key string) string {
	return v.m[key]
}

func (s *server) authadmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.Respond(w, r, http.StatusUnauthorized, errors.New("Token não fornecido"))
			return
		}

		// Remove o prefixo "Bearer " se existir
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token != *adminToken {
			s.Respond(w, r, http.StatusUnauthorized, errors.New("Token inválido"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) authalice(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var ctx context.Context
		userid := 0
		txtid := ""
		webhook := ""
		jid := ""
		events := ""

		// Get token from headers or uri parameters
		token := r.Header.Get("token")
		if token == "" {
			token = strings.Join(r.URL.Query()["token"], "")
		}

		myuserinfo, found := userinfocache.Get(token)
		if !found {
			log.Info().Msg("Looking for user information in DB")
			// Checks DB from matching user and store user values in context
			rows, err := s.db.Query("SELECT id,webhook,jid,events FROM users WHERE token=$1 LIMIT 1", token)
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, err)
				return
			}
			defer rows.Close()
			for rows.Next() {
				err = rows.Scan(&txtid, &webhook, &jid, &events)
				if err != nil {
					s.Respond(w, r, http.StatusInternalServerError, err)
					return
				}
				userid, _ = strconv.Atoi(txtid)
				v := Values{map[string]string{
					"Id":      txtid,
					"Jid":     jid,
					"Webhook": webhook,
					"Token":   token,
					"Events":  events,
				}}

				userinfocache.Set(token, v, cache.NoExpiration)
				ctx = context.WithValue(r.Context(), "userinfo", v)
			}
		} else {
			ctx = context.WithValue(r.Context(), "userinfo", myuserinfo)
			userid, _ = strconv.Atoi(myuserinfo.(Values).Get("Id"))
		}

		if userid == 0 {
			s.Respond(w, r, http.StatusUnauthorized, errors.New("Unauthorized"))
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Middleware: Authenticate connections based on Token header/uri parameter
func (s *server) auth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var ctx context.Context
		userid := 0
		txtid := ""
		webhook := ""
		jid := ""
		events := ""

		// Get token from headers or uri parameters
		token := r.Header.Get("token")
		if token == "" {
			token = strings.Join(r.URL.Query()["token"], "")
		}

		myuserinfo, found := userinfocache.Get(token)
		if !found {
			log.Info().Msg("Looking for user information in DB")
			// Checks DB from matching user and store user values in context
			rows, err := s.db.Query("SELECT id, webhook, jid, events FROM users WHERE token=$1 LIMIT 1", token)
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, err)
				return
			}
			defer rows.Close()
			for rows.Next() {
				err = rows.Scan(&txtid, &webhook, &jid, &events)
				if err != nil {
					s.Respond(w, r, http.StatusInternalServerError, err)
					return
				}
				userid, _ = strconv.Atoi(txtid)
				v := Values{map[string]string{
					"Id":      txtid,
					"Jid":     jid,
					"Webhook": webhook,
					"Token":   token,
					"Events":  events,
				}}

				userinfocache.Set(token, v, cache.NoExpiration)
				ctx = context.WithValue(r.Context(), "userinfo", v)
			}
		} else {
			ctx = context.WithValue(r.Context(), "userinfo", myuserinfo)
			userid, _ = strconv.Atoi(myuserinfo.(Values).Get("Id"))
		}

		if userid == 0 {
			s.Respond(w, r, http.StatusUnauthorized, errors.New("Unauthorized"))
			return
		}
		handler(w, r.WithContext(ctx))
	}
}

// Connects to Whatsapp Servers
func (s *server) Connect() http.HandlerFunc {

	type connectRequest struct {
		Subscribe []string `json:"subscribe"`
		Immediate bool     `json:"immediate"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Extrair IDs do contexto e da URL
		supabaseUserID, ok := r.Context().Value("supabase_user_id").(string)
		if !ok || supabaseUserID == "" {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("não foi possível identificar o usuário na requisição"))
			return
		}

		vars := mux.Vars(r)
		instanceID, err := strconv.Atoi(vars["id"])
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("ID da instância inválido"))
			return
		}

		// 2. Buscar a instância e verificar a posse usando o repositório
		repo := repository.NewPostgresRepository(s.db)
		instance, err := repo.GetInstance(instanceID, supabaseUserID)
		if err != nil {
			s.Respond(w, r, http.StatusNotFound, err) // O erro do repo já é "não encontrada ou não pertence"
			return
		}

		// 3. Decodificar o corpo da requisição
		var req connectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		// 4. Verificar se a instância já está conectada
		if clientPointer[instance.ID] != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Already Connected"))
			return
		}

		// 5. Lógica de subscrição de eventos (adaptada)
		var subscribedEvents []string
		if len(req.Subscribe) < 1 {
			if !Find(subscribedEvents, "All") {
				subscribedEvents = append(subscribedEvents, "All")
			}
		} else {
			for _, arg := range req.Subscribe {
				if !isValidEventType(arg) {
					log.Warn().Str("Type", arg).Msg("Message type discarded")
					continue
				}
				if !Find(subscribedEvents, arg) {
					subscribedEvents = append(subscribedEvents, arg)
				}
			}
		}
		eventstring := strings.Join(subscribedEvents, ",")

		// TODO: Mover esta lógica para o repositório
		_, err = s.db.Exec("UPDATE users SET events=$1 WHERE id=$2 AND supabase_user_id=$3", eventstring, instance.ID, supabaseUserID)
		if err != nil {
			log.Warn().Msg("Could not set events in users table")
			// Não retornar erro aqui, apenas logar
		}
		log.Info().Str("events", eventstring).Msg("Setting subscribed events")

		// O cache antigo `userinfocache` deve ser descontinuado ou repensado. Por agora, vamos ignorá-lo.

		// 6. Iniciar o cliente whatsmeow
		log.Info().Str("jid", instance.Jid).Msg("Attempt to connect")
		killchannel[instance.ID] = make(chan bool)
		go s.startClient(instance.ID, instance.Jid, instance.Token, subscribedEvents)

		if !req.Immediate {
			log.Warn().Msg("Waiting 10 seconds")
			time.Sleep(10 * time.Second)

			if clientPointer[instance.ID] == nil || !clientPointer[instance.ID].IsConnected() {
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Failed to Connect"))
				return
			}
		}

		// 7. Responder com sucesso
		response := map[string]interface{}{"webhook": instance.Webhook, "jid": instance.Jid, "events": eventstring, "details": "Connected!"}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}

// Disconnects from Whatsapp websocket, does not log out device
func (s *server) Disconnect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Extrair IDs e verificar posse
		supabaseUserID, ok := r.Context().Value("supabase_user_id").(string)
		if !ok || supabaseUserID == "" {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("não foi possível identificar o usuário na requisição"))
			return
		}

		vars := mux.Vars(r)
		instanceID, err := strconv.Atoi(vars["id"])
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("ID da instância inválido"))
			return
		}

		repo := repository.NewPostgresRepository(s.db)
		instance, err := repo.GetInstance(instanceID, supabaseUserID)
		if err != nil {
			s.Respond(w, r, http.StatusNotFound, err)
			return
		}

		// 2. Lógica de desconexão
		if clientPointer[instance.ID] != nil && clientPointer[instance.ID].IsConnected() && clientPointer[instance.ID].IsLoggedIn() {
			log.Info().Str("jid", instance.Jid).Msg("Disconnection successful")

			// Envia o webhook de desconexão antes de matar o cliente
			if instance.Webhook != "" {
				postmap := make(map[string]interface{})
				postmap["type"] = "Disconnected"
				postmap["event"] = map[string]interface{}{}

				jsonData, err := json.Marshal(postmap)
				if err == nil {
					data := map[string]string{
						"jsonData": string(jsonData),
						"token":    instance.Token,
					}
					log.Info().Str("url", instance.Webhook).Str("eventType", "Disconnected").Msg("Sending Disconnected webhook")
					go callHook(instance.Webhook, data, instance.ID)
				}
			}

			killchannel[instance.ID] <- true

			// 3. Limpar eventos usando o repositório
			if err := repo.ClearInstanceEvents(instance.ID, supabaseUserID); err != nil {
				log.Warn().Str("instance_id", vars["id"]).Msg("Could not clear events in users table")
			}

			// O cache antigo será removido/ignorado
			userinfocache.Delete(instance.Token)

			response := map[string]interface{}{"Details": "Disconnected"}
			responseJson, err := json.Marshal(response)
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, err)
			} else {
				s.Respond(w, r, http.StatusOK, string(responseJson))
			}
		} else {
			log.Warn().Str("jid", instance.Jid).Msg("Ignoring disconnect as it was not connected/logged in")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Cannot disconnect because it is not logged in or connected"))
		}
	}
}

// Gets WebHook
func (s *server) GetWebhook() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		webhook := ""
		events := ""
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		rows, err := s.db.Query("SELECT webhook,events FROM users WHERE id=$1 LIMIT 1", txtid)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not get webhook: %v", err)))
			return
		}
		defer rows.Close()
		for rows.Next() {
			err = rows.Scan(&webhook, &events)
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not get webhook: %s", fmt.Sprintf("%s", err))))
				return
			}
		}
		err = rows.Err()
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not get webhook: %s", fmt.Sprintf("%s", err))))
			return
		}

		eventarray := strings.Split(events, ",")

		response := map[string]interface{}{"webhook": webhook, "subscribe": eventarray}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// DeleteWebhook removes the webhook and clears events for a user
func (s *server) DeleteWebhook() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		token := r.Context().Value("userinfo").(Values).Get("Token")
		userid, _ := strconv.Atoi(txtid)

		// Update the database to remove the webhook and clear events
		_, err := s.db.Exec("UPDATE users SET webhook='', events='' WHERE id=$1", userid)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not delete webhook: %v", err)))
			return
		}

		// Update the user info cache
		v := updateUserInfo(r.Context().Value("userinfo"), "Webhook", "")
		v = updateUserInfo(v, "Events", "")
		userinfocache.Set(token, v, cache.NoExpiration)

		response := map[string]interface{}{"Details": "Webhook and events deleted successfully"}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}

// UpdateWebhook updates the webhook URL and events for a user
func (s *server) UpdateWebhook() http.HandlerFunc {
	type updateWebhookStruct struct {
		WebhookURL string   `json:"webhook"`
		Events     []string `json:"events"`
		Active     bool     `json:"active"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		token := r.Context().Value("userinfo").(Values).Get("Token")
		userid, _ := strconv.Atoi(txtid)

		decoder := json.NewDecoder(r.Body)
		var t updateWebhookStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		webhook := t.WebhookURL
		events := strings.Join(t.Events, ",")
		if !t.Active {
			webhook = ""
			events = ""
		}

		_, err = s.db.Exec("UPDATE users SET webhook=?, events=? WHERE id=?", webhook, events, userid)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not update webhook: %v", err)))
			return
		}

		v := updateUserInfo(r.Context().Value("userinfo"), "Webhook", webhook)
		v = updateUserInfo(v, "Events", events)
		userinfocache.Set(token, v, cache.NoExpiration)

		response := map[string]interface{}{"webhook": webhook, "events": t.Events, "active": t.Active}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}

// SetWebhook sets the webhook URL and events for a user
func (s *server) SetWebhook() http.HandlerFunc {
	type webhookStruct struct {
		WebhookURL string   `json:"webhook"`
		Events     []string `json:"events"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		token := r.Context().Value("userinfo").(Values).Get("Token")
		userid, _ := strconv.Atoi(txtid)

		decoder := json.NewDecoder(r.Body)
		var t webhookStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		webhook := t.WebhookURL
		events := strings.Join(t.Events, ",")

		_, err = s.db.Exec("UPDATE users SET webhook=$1, events=$2 WHERE id=$3", webhook, events, userid)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not set webhook: %v", err)))
			return
		}

		v := updateUserInfo(r.Context().Value("userinfo"), "Webhook", webhook)
		v = updateUserInfo(v, "Events", events)
		userinfocache.Set(token, v, cache.NoExpiration)

		response := map[string]interface{}{"webhook": webhook, "events": t.Events}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}

// GetQR busca o código QR para uma instância específica do usuário autenticado.
func (s *server) GetQR() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Extrair IDs e verificar posse (indiretamente, via repositório)
		supabaseUserID, ok := r.Context().Value("supabase_user_id").(string)
		if !ok || supabaseUserID == "" {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("não foi possível identificar o usuário na requisição"))
			return
		}

		vars := mux.Vars(r)
		instanceID, err := strconv.Atoi(vars["id"])
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("ID da instância inválido"))
			return
		}

		// 2. Verificar estado da conexão em memória
		if clientPointer[instanceID] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}
		if !clientPointer[instanceID].IsConnected() {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Not connected"))
			return
		}
		if clientPointer[instanceID].IsLoggedIn() {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Already Loggedin"))
			return
		}

		// 3. Buscar o QR code no banco de dados de forma segura
		repo := repository.NewPostgresRepository(s.db)
		code, err := repo.GetInstanceQRCode(instanceID, supabaseUserID)
		if err != nil {
			s.Respond(w, r, http.StatusNotFound, err) // O erro do repo já é "não encontrada ou não pertence"
			return
		}

		// 4. Retornar o QR code
		log.Info().Int("instanceID", instanceID).Str("qrcode", code).Msg("Get QR successful")
		response := map[string]interface{}{"QRCode": code}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}

// Logs out device from Whatsapp (requires to scan QR next time)
func (s *server) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Extrair IDs e verificar posse
		supabaseUserID, ok := r.Context().Value("supabase_user_id").(string)
		if !ok || supabaseUserID == "" {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("não foi possível identificar o usuário na requisição"))
			return
		}

		vars := mux.Vars(r)
		instanceID, err := strconv.Atoi(vars["id"])
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("ID da instância inválido"))
			return
		}

		repo := repository.NewPostgresRepository(s.db)
		instance, err := repo.GetInstance(instanceID, supabaseUserID)
		if err != nil {
			s.Respond(w, r, http.StatusNotFound, err)
			return
		}

		// 2. Lógica de Logout
		if clientPointer[instance.ID] != nil && clientPointer[instance.ID].IsConnected() && clientPointer[instance.ID].IsLoggedIn() {
			err := clientPointer[instance.ID].Logout(r.Context())
			if err != nil {
				log.Error().Str("jid", instance.Jid).Msg("Could not perform logout")
				s.Respond(w, r, http.StatusInternalServerError, errors.New("Could not perform logout"))
				return
			}

			log.Info().Str("jid", instance.Jid).Msg("Logged out")

			// Envia o webhook de logout
			if instance.Webhook != "" {
				postmap := make(map[string]interface{})
				postmap["type"] = "LoggedOut"
				postmap["event"] = map[string]interface{}{}

				jsonData, err := json.Marshal(postmap)
				if err == nil {
					data := map[string]string{
						"jsonData": string(jsonData),
						"token":    instance.Token,
					}
					log.Info().Str("url", instance.Webhook).Str("eventType", "LoggedOut").Msg("Sending LoggedOut webhook")
					go callHook(instance.Webhook, data, instance.ID)
				}
			}

			killchannel[instance.ID] <- true
		} else {
			log.Warn().Str("jid", instance.Jid).Msg("Ignoring logout as it was not connected/logged in")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Could not perform logout as it was not connected/logged in"))
			return
		}

		response := map[string]interface{}{"Details": "Logged out"}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}

// Pair by Phone. Retrieves the code to pair by phone number instead of QR
func (s *server) PairPhone() http.HandlerFunc {

	type pairStruct struct {
		Phone string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t pairStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		isLoggedIn := clientPointer[userid].IsLoggedIn()
		if isLoggedIn {
			log.Error().Msg(fmt.Sprintf("%s", "Already paired"))
			s.Respond(w, r, http.StatusBadRequest, errors.New("Already paired"))
			return
		}

		linkingCode, err := clientPointer[userid].PairPhone(r.Context(), t.Phone, true, whatsmeow.PairClientChrome, "Chrome (Linux)")
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		response := map[string]interface{}{"LinkingCode": linkingCode}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Gets Connected and LoggedIn Status
func (s *server) GetStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Extrair IDs e verificar posse
		supabaseUserID, ok := r.Context().Value("supabase_user_id").(string)
		if !ok || supabaseUserID == "" {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("não foi possível identificar o usuário na requisição"))
			return
		}

		vars := mux.Vars(r)
		instanceID, err := strconv.Atoi(vars["id"])
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("ID da instância inválido"))
			return
		}

		repo := repository.NewPostgresRepository(s.db)
		instance, err := repo.GetInstance(instanceID, supabaseUserID)
		if err != nil {
			s.Respond(w, r, http.StatusNotFound, err)
			return
		}

		// 2. Lógica de verificação de status
		if clientPointer[instance.ID] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		isConnected := clientPointer[instance.ID].IsConnected()
		isLoggedIn := clientPointer[instance.ID].IsLoggedIn()

		response := map[string]interface{}{"Connected": isConnected, "LoggedIn": isLoggedIn}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}

// Sends a document/attachment message
func (s *server) SendDocument() http.HandlerFunc {

	type documentStruct struct {
		Caption     string
		Phone       string
		Document    string
		FileName    string
		Id          string
		ContextInfo waProto.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)
		msgid := ""
		var resp whatsmeow.SendResponse

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t documentStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Document == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Document in Payload"))
			return
		}

		if t.FileName == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing FileName in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var uploaded whatsmeow.UploadResponse
		var filedata []byte

		if t.Document[0:29] == "data:application/octet-stream" {
			dataURL, err := dataurl.DecodeString(t.Document)
			if err != nil {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode base64 encoded data from payload"))
				return
			} else {
				filedata = dataURL.Data
				uploaded, err = clientPointer[userid].Upload(r.Context(), filedata, whatsmeow.MediaDocument)
				if err != nil {
					s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to upload file: %v", err)))
					return
				}
			}
		} else {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Document data should start with \"data:application/octet-stream;base64,\""))
			return
		}

		msg := &waProto.Message{DocumentMessage: &waProto.DocumentMessage{
			URL:           proto.String(uploaded.URL),
			FileName:      &t.FileName,
			DirectPath:    proto.String(uploaded.DirectPath),
			MediaKey:      uploaded.MediaKey,
			Mimetype:      proto.String(http.DetectContentType(filedata)),
			FileEncSHA256: uploaded.FileEncSHA256,
			FileSHA256:    uploaded.FileSHA256,
			FileLength:    proto.Uint64(uint64(len(filedata))),
			Caption:       proto.String(t.Caption),
		}}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waProto.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waProto.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waProto.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientPointer[userid].SendMessage(r.Context(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends an audio message
func (s *server) SendAudio() http.HandlerFunc {

	type audioStruct struct {
		Phone       string
		Audio       string
		Caption     string
		Id          string
		ContextInfo waProto.ContextInfo
		Seconds     uint32
		Waveform    []byte
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)
		msgid := ""
		var resp whatsmeow.SendResponse

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t audioStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Audio == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Audio in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var uploaded whatsmeow.UploadResponse
		var filedata []byte

		if t.Audio[0:14] == "data:audio/ogg" {
			dataURL, err := dataurl.DecodeString(t.Audio)
			if err != nil {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode base64 encoded data from payload"))
				return
			} else {
				filedata = dataURL.Data
				uploaded, err = clientPointer[userid].Upload(r.Context(), filedata, whatsmeow.MediaAudio)
				if err != nil {
					s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to upload file: %v", err)))
					return
				}
			}
		} else {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Audio data should start with \"data:audio/ogg;base64,\""))
			return
		}

		ptt := true
		mime := "audio/ogg; codecs=opus"

		msg := &waProto.Message{AudioMessage: &waProto.AudioMessage{
			URL:        proto.String(uploaded.URL),
			DirectPath: proto.String(uploaded.DirectPath),
			MediaKey:   uploaded.MediaKey,
			//Mimetype:      proto.String(http.DetectContentType(filedata)),
			Mimetype:      &mime,
			FileEncSHA256: uploaded.FileEncSHA256,
			FileSHA256:    uploaded.FileSHA256,
			FileLength:    proto.Uint64(uint64(len(filedata))),
			PTT:           &ptt,
			Seconds:       proto.Uint32(t.Seconds),
			Waveform:      t.Waveform,
		}}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waProto.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waProto.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waProto.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientPointer[userid].SendMessage(r.Context(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends an Image message
func (s *server) SendImage() http.HandlerFunc {

	type imageStruct struct {
		Phone       string
		Image       string
		Caption     string
		Id          string
		ContextInfo waProto.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)
		msgid := ""
		var resp whatsmeow.SendResponse

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t imageStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Image == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Image in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var uploaded whatsmeow.UploadResponse
		var filedata []byte
		var thumbnailBytes []byte

		if t.Image[0:10] == "data:image" {
			dataURL, err := dataurl.DecodeString(t.Image)
			if err != nil {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode base64 encoded data from payload"))
				return
			} else {
				filedata = dataURL.Data
				uploaded, err = clientPointer[userid].Upload(r.Context(), filedata, whatsmeow.MediaImage)
				if err != nil {
					s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to upload file: %v", err)))
					return
				}
			}

			// decode jpeg into image.Image
			reader := bytes.NewReader(filedata)
			img, _, err := image.Decode(reader)
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not decode image for thumbnail preparation: %v", err)))
				return
			}

			// resize to width 72 using Lanczos resampling and preserve aspect ratio
			m := resize.Thumbnail(72, 72, img, resize.Lanczos3)

			tmpFile, err := os.CreateTemp("", "resized-*.jpg")
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not create temp file for thumbnail: %v", err)))
				return
			}
			defer tmpFile.Close()

			// write new image to file
			if err := jpeg.Encode(tmpFile, m, nil); err != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to encode jpeg: %v", err)))
				return
			}

			thumbnailBytes, err = os.ReadFile(tmpFile.Name())
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to read %s: %v", tmpFile.Name(), err)))
				return
			}

		} else {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Image data should start with \"data:image/png;base64,\""))
			return
		}

		msg := &waProto.Message{ImageMessage: &waProto.ImageMessage{
			Caption:       proto.String(t.Caption),
			URL:           proto.String(uploaded.URL),
			DirectPath:    proto.String(uploaded.DirectPath),
			MediaKey:      uploaded.MediaKey,
			Mimetype:      proto.String(http.DetectContentType(filedata)),
			FileEncSHA256: uploaded.FileEncSHA256,
			FileSHA256:    uploaded.FileSHA256,
			FileLength:    proto.Uint64(uint64(len(filedata))),
			JPEGThumbnail: thumbnailBytes,
		}}

		if t.ContextInfo.StanzaID != nil {
			if msg.ImageMessage.ContextInfo == nil {
				msg.ImageMessage.ContextInfo = &waProto.ContextInfo{
					StanzaID:      proto.String(*t.ContextInfo.StanzaID),
					Participant:   proto.String(*t.ContextInfo.Participant),
					QuotedMessage: &waProto.Message{Conversation: proto.String("")},
				}
			}
		}

		if t.ContextInfo.MentionedJID != nil {
			msg.ImageMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientPointer[userid].SendMessage(r.Context(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Send Pool
func (s *server) SendPoll() http.HandlerFunc {
	type pollRequest struct {
		Group   string   `json:"group"`   // The recipient's group id (120363313346913103@g.us)
		Header  string   `json:"header"`  // The poll's headline text
		Options []string `json:"options"` // The list of poll options
		Id      string
	}

	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var req pollRequest
		err := decoder.Decode(&req)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode payload"))
			return
		}

		if req.Group == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Grouop in payload"))
			return
		}

		if req.Header == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Header in payload"))
			return
		}

		if len(req.Options) < 2 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("At least 2 options are required"))
			return
		}

		if req.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = req.Id
		}

		recipient, err := validateMessageFields(req.Group, nil, nil)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		pollMessage := clientPointer[userid].BuildPollCreation(req.Header, req.Options, 1)
		resp, err = clientPointer[userid].SendMessage(r.Context(), recipient, pollMessage, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to send poll: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%v", resp.Timestamp)).Str("id", msgid).Msg("Poll sent")

		response := map[string]interface{}{"Details": "Poll sent successfully", "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}

// Join group invite link
func (s *server) GroupJoin() http.HandlerFunc {

	type joinGroupStruct struct {
		Code string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t joinGroupStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Code == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Code in Payload"))
			return
		}

		_, err = clientPointer[userid].JoinGroupWithLink(t.Code)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to join group")
			msg := fmt.Sprintf("Failed to join group: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group joined successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Set group topic (description)
func (s *server) SetGroupTopic() http.HandlerFunc {

	type setGroupTopicStruct struct {
		GroupJID string
		Topic    string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t setGroupTopicStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		if t.Topic == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Topic in Payload"))
			return
		}

		err = clientPointer[userid].SetGroupTopic(group, "", "", t.Topic)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to set group topic")
			msg := fmt.Sprintf("Failed to set group topic: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group Topic set successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

func (s *server) GroupLeave() http.HandlerFunc {

	type groupLeaveStruct struct {
		GroupJID string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t groupLeaveStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		err = clientPointer[userid].LeaveGroup(group)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to leave group")
			msg := fmt.Sprintf("Failed to leave group: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group left successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// SetGroupAnnounce post
func (s *server) SetGroupAnnounce() http.HandlerFunc {

	type setGroupAnnounceStruct struct {
		GroupJID string
		Announce bool
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t setGroupAnnounceStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		err = clientPointer[userid].SetGroupAnnounce(group, t.Announce)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to set group announce")
			msg := fmt.Sprintf("Failed to set group announce: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group Announce set successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// add, remove, promote and demote members group
func (s *server) UpdateGroupParticipants() http.HandlerFunc {

	type updateGroupParticipantsStruct struct {
		GroupJID string
		Phone    []string
		// Action string // add, remove, promote, demote
		Action string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t updateGroupParticipantsStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		if len(t.Phone) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}
		// parse phone numbers
		phoneParsed := make([]types.JID, len(t.Phone))
		for i, phone := range t.Phone {
			phoneParsed[i], ok = parseJID(phone)
			if !ok {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Phone"))
				return
			}
		}

		if t.Action == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Action in Payload"))
			return
		}

		// parse action

		var action whatsmeow.ParticipantChange
		switch t.Action {
		case "add":
			action = "add"
		case "remove":
			action = "remove"
		case "promote":
			action = "promote"
		case "demote":
			action = "demote"
		default:
			s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid Action in Payload"))
			return
		}

		_, err = clientPointer[userid].UpdateGroupParticipants(group, phoneParsed, action)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to change participant group")
			msg := fmt.Sprintf("Failed to change participant group: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group Participants updated successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Get group invite info
func (s *server) GetGroupInviteInfo() http.HandlerFunc {

	type getGroupInviteInfoStruct struct {
		Code string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t getGroupInviteInfoStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Code == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Code in Payload"))
			return
		}

		groupInfo, err := clientPointer[userid].GetGroupInfoFromLink(t.Code)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to get group invite info")
			msg := fmt.Sprintf("Failed to get group invite info: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		responseJson, err := json.Marshal(groupInfo)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Create group
func (s *server) CreateGroup() http.HandlerFunc {

	type createGroupStruct struct {
		Name         string   `json:"name"`
		Participants []string `json:"participants"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t createGroupStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Name == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Name in Payload"))
			return
		}

		if len(t.Participants) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Participants in Payload"))
			return
		}

		// Parse participant phone numbers
		participantJIDs := make([]types.JID, len(t.Participants))
		var ok bool
		for i, phone := range t.Participants {
			participantJIDs[i], ok = parseJID(phone)
			if !ok {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Participant Phone"))
				return
			}
		}

		req := whatsmeow.ReqCreateGroup{
			Name:         t.Name,
			Participants: participantJIDs,
		}

		groupInfo, err := clientPointer[userid].CreateGroup(r.Context(), req)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to create group")
			msg := fmt.Sprintf("Failed to create group: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		responseJson, err := json.Marshal(groupInfo)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Set group locked
func (s *server) SetGroupLocked() http.HandlerFunc {

	type setGroupLockedStruct struct {
		GroupJID string `json:"groupjid"`
		Locked   bool   `json:"locked"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t setGroupLockedStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		err = clientPointer[userid].SetGroupLocked(group, t.Locked)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to set group locked")
			msg := fmt.Sprintf("Failed to set group locked: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group Locked setting updated successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Set disappearing timer (ephemeral messages)
func (s *server) SetDisappearingTimer() http.HandlerFunc {

	type setDisappearingTimerStruct struct {
		GroupJID string `json:"groupjid"`
		Duration string `json:"duration"` // "24h", "7d", "90d", "off"
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t setDisappearingTimerStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		if t.Duration == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Duration in Payload"))
			return
		}

		var duration time.Duration
		switch t.Duration {
		case "24h":
			duration = 24 * time.Hour
		case "7d":
			duration = 7 * 24 * time.Hour
		case "90d":
			duration = 90 * 24 * time.Hour
		case "off":
			duration = 0
		default:
			s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid duration. Use: 24h, 7d, 90d, or off"))
			return
		}

		err = clientPointer[userid].SetDisappearingTimer(group, duration, time.Now())

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to set disappearing timer")
			msg := fmt.Sprintf("Failed to set disappearing timer: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Disappearing timer set successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Remove group photo
func (s *server) RemoveGroupPhoto() http.HandlerFunc {

	type removeGroupPhotoStruct struct {
		GroupJID string `json:"groupjid"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t removeGroupPhotoStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		_, err = clientPointer[userid].SetGroupPhoto(group, nil)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to remove group photo")
			msg := fmt.Sprintf("Failed to remove group photo: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group Photo removed successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Sends Sticker message
func (s *server) SendSticker() http.HandlerFunc {

	type stickerStruct struct {
		Phone        string
		Sticker      string
		Id           string
		PngThumbnail []byte
		ContextInfo  waProto.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)
		msgid := ""
		var resp whatsmeow.SendResponse

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t stickerStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Sticker == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Sticker in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var uploaded whatsmeow.UploadResponse
		var filedata []byte

		if t.Sticker[0:4] == "data" {
			dataURL, err := dataurl.DecodeString(t.Sticker)
			if err != nil {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode base64 encoded data from payload"))
				return
			} else {
				filedata = dataURL.Data
				uploaded, err = clientPointer[userid].Upload(r.Context(), filedata, whatsmeow.MediaImage)
				if err != nil {
					s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to upload file: %v", err)))
					return
				}
			}
		} else {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Data should start with \"data:mime/type;base64,\""))
			return
		}

		msg := &waProto.Message{StickerMessage: &waProto.StickerMessage{
			URL:           proto.String(uploaded.URL),
			DirectPath:    proto.String(uploaded.DirectPath),
			MediaKey:      uploaded.MediaKey,
			Mimetype:      proto.String(http.DetectContentType(filedata)),
			FileEncSHA256: uploaded.FileEncSHA256,
			FileSHA256:    uploaded.FileSHA256,
			FileLength:    proto.Uint64(uint64(len(filedata))),
			PngThumbnail:  t.PngThumbnail,
		}}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waProto.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waProto.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waProto.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientPointer[userid].SendMessage(r.Context(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends Video message
func (s *server) SendVideo() http.HandlerFunc {

	type imageStruct struct {
		Phone         string
		Video         string
		Caption       string
		Id            string
		JPEGThumbnail []byte
		ContextInfo   waProto.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)
		msgid := ""
		var resp whatsmeow.SendResponse

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t imageStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Video == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Video in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var uploaded whatsmeow.UploadResponse
		var filedata []byte

		if t.Video[0:4] == "data" {
			dataURL, err := dataurl.DecodeString(t.Video)
			if err != nil {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode base64 encoded data from payload"))
				return
			} else {
				filedata = dataURL.Data
				uploaded, err = clientPointer[userid].Upload(r.Context(), filedata, whatsmeow.MediaVideo)
				if err != nil {
					s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to upload file: %v", err)))
					return
				}
			}
		} else {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Data should start with \"data:mime/type;base64,\""))
			return
		}

		msg := &waProto.Message{VideoMessage: &waProto.VideoMessage{
			Caption:       proto.String(t.Caption),
			URL:           proto.String(uploaded.URL),
			DirectPath:    proto.String(uploaded.DirectPath),
			MediaKey:      uploaded.MediaKey,
			Mimetype:      proto.String(http.DetectContentType(filedata)),
			FileEncSHA256: uploaded.FileEncSHA256,
			FileSHA256:    uploaded.FileSHA256,
			FileLength:    proto.Uint64(uint64(len(filedata))),
			JPEGThumbnail: t.JPEGThumbnail,
		}}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waProto.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waProto.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waProto.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientPointer[userid].SendMessage(r.Context(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends Contact
func (s *server) SendContact() http.HandlerFunc {

	type contactStruct struct {
		Phone       string
		Id          string
		Name        string
		Vcard       string
		ContextInfo waProto.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var t contactStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}
		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}
		if t.Name == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Name in Payload"))
			return
		}
		if t.Vcard == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Vcard in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		msg := &waProto.Message{ContactMessage: &waProto.ContactMessage{
			DisplayName: &t.Name,
			Vcard:       &t.Vcard,
		}}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waProto.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waProto.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waProto.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientPointer[userid].SendMessage(r.Context(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends location
func (s *server) SendLocation() http.HandlerFunc {

	type locationStruct struct {
		Phone       string
		Id          string
		Name        string
		Latitude    float64
		Longitude   float64
		ContextInfo waProto.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var t locationStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}
		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}
		if t.Latitude == 0 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Latitude in Payload"))
			return
		}
		if t.Longitude == 0 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Longitude in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		msg := &waProto.Message{LocationMessage: &waProto.LocationMessage{
			DegreesLatitude:  &t.Latitude,
			DegreesLongitude: &t.Longitude,
			Name:             &t.Name,
		}}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waProto.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waProto.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waProto.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientPointer[userid].SendMessage(r.Context(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends Buttons (not implemented, does not work)

func (s *server) SendButtons() http.HandlerFunc {

	type buttonStruct struct {
		ButtonId   string
		ButtonText string
	}
	type textStruct struct {
		Phone   string
		Title   string
		Buttons []buttonStruct
		Id      string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var t textStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Title == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Title in Payload"))
			return
		}

		if len(t.Buttons) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Buttons in Payload"))
			return
		}
		if len(t.Buttons) > 3 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("buttons cant more than 3"))
			return
		}

		recipient, ok := parseJID(t.Phone)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Phone"))
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var buttons []*waProto.ButtonsMessage_Button

		for _, item := range t.Buttons {
			buttons = append(buttons, &waProto.ButtonsMessage_Button{
				ButtonID:       proto.String(item.ButtonId),
				ButtonText:     &waProto.ButtonsMessage_Button_ButtonText{DisplayText: proto.String(item.ButtonText)},
				Type:           waProto.ButtonsMessage_Button_RESPONSE.Enum(),
				NativeFlowInfo: &waProto.ButtonsMessage_Button_NativeFlowInfo{},
			})
		}

		msg2 := &waProto.ButtonsMessage{
			ContentText: proto.String(t.Title),
			HeaderType:  waProto.ButtonsMessage_EMPTY.Enum(),
			Buttons:     buttons,
		}

		resp, err = clientPointer[userid].SendMessage(r.Context(), recipient, &waProto.Message{ViewOnceMessage: &waProto.FutureProofMessage{
			Message: &waProto.Message{
				ButtonsMessage: msg2,
			},
		}}, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// SendList
// https://github.com/tulir/whatsmeow/issues/305
func (s *server) SendList() http.HandlerFunc {

	type rowsStruct struct {
		RowId       string
		Title       string
		Description string
	}

	type sectionsStruct struct {
		Title string
		Rows  []rowsStruct
	}

	type listStruct struct {
		Phone       string
		Title       string
		Description string
		ButtonText  string
		FooterText  string
		Sections    []sectionsStruct
		Id          string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var t listStruct
		err := decoder.Decode(&t)
		marshal, _ := json.Marshal(t)
		fmt.Println(string(marshal))
		if err != nil {
			fmt.Println(err)
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Phone in Payload"))
			return
		}

		if t.Title == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Title in Payload"))
			return
		}

		if t.Description == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Description in Payload"))
			return
		}

		if t.ButtonText == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing ButtonText in Payload"))
			return
		}

		if len(t.Sections) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Sections in Payload"))
			return
		}
		recipient, ok := parseJID(t.Phone)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Phone"))
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var sections []*waProto.ListMessage_Section

		for _, item := range t.Sections {
			var rows []*waProto.ListMessage_Row
			id := 1
			for _, row := range item.Rows {
				var idtext string
				if row.RowId == "" {
					idtext = strconv.Itoa(id)
				} else {
					idtext = row.RowId
				}
				rows = append(rows, &waProto.ListMessage_Row{
					RowID:       proto.String(idtext),
					Title:       proto.String(row.Title),
					Description: proto.String(row.Description),
				})
			}

			sections = append(sections, &waProto.ListMessage_Section{
				Title: proto.String(item.Title),
				Rows:  rows,
			})
		}
		msg1 := &waProto.ListMessage{
			Title:       proto.String(t.Title),
			Description: proto.String(t.Description),
			ButtonText:  proto.String(t.ButtonText),
			ListType:    waProto.ListMessage_SINGLE_SELECT.Enum(),
			Sections:    sections,
			FooterText:  proto.String(t.FooterText),
		}

		resp, err = clientPointer[userid].SendMessage(r.Context(), recipient, &waProto.Message{
			ViewOnceMessage: &waProto.FutureProofMessage{
				Message: &waProto.Message{
					ListMessage: msg1,
				},
			}}, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Sends a regular text message
func (s *server) SendMessage() http.HandlerFunc {

	type textStruct struct {
		Phone       string
		Body        string
		Id          string
		ContextInfo waProto.ContextInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse

		decoder := json.NewDecoder(r.Body)
		var t textStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Body == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Body in Payload"))
			return
		}

		recipient, err := validateMessageFields(t.Phone, t.ContextInfo.StanzaID, t.ContextInfo.Participant)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%s", err))
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		//	msg := &waProto.Message{Conversation: &t.Body}

		msg := &waProto.Message{
			ExtendedTextMessage: &waProto.ExtendedTextMessage{
				Text: &t.Body,
			},
		}

		if t.ContextInfo.StanzaID != nil {
			msg.ExtendedTextMessage.ContextInfo = &waProto.ContextInfo{
				StanzaID:      proto.String(*t.ContextInfo.StanzaID),
				Participant:   proto.String(*t.ContextInfo.Participant),
				QuotedMessage: &waProto.Message{Conversation: proto.String("")},
			}
		}
		if t.ContextInfo.MentionedJID != nil {
			if msg.ExtendedTextMessage.ContextInfo == nil {
				msg.ExtendedTextMessage.ContextInfo = &waProto.ContextInfo{}
			}
			msg.ExtendedTextMessage.ContextInfo.MentionedJID = t.ContextInfo.MentionedJID
		}

		resp, err = clientPointer[userid].SendMessage(r.Context(), recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

/*
// Sends a Template message
func (s *server) SendTemplate() http.HandlerFunc {

	type buttonStruct struct {
		DisplayText string
		Id          string
		Url         string
		PhoneNumber string
		Type        string
	}

	type templateStruct struct {
		Phone   string
		Content string
		Footer  string
		Id      string
		Buttons []buttonStruct
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		msgid := ""
		var resp whatsmeow.SendResponse
//var ts time.Time

		decoder := json.NewDecoder(r.Body)
		var t templateStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if t.Content == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Content in Payload"))
			return
		}

		if t.Footer == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Footer in Payload"))
			return
		}

		if len(t.Buttons) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Buttons in Payload"))
			return
		}

		recipient, ok := parseJID(t.Phone)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Phone"))
			return
		}

		if t.Id == "" {
			msgid = whatsmeow.GenerateMessageID()
		} else {
			msgid = t.Id
		}

		var buttons []*waProto.HydratedTemplateButton

		id := 1
		for _, item := range t.Buttons {
			switch item.Type {
			case "quickreply":
				var idtext string
				text := item.DisplayText
				if item.Id == "" {
					idtext = strconv.Itoa(id)
				} else {
					idtext = item.Id
				}
				buttons = append(buttons, &waProto.HydratedTemplateButton{
					HydratedButton: &waProto.HydratedTemplateButton_QuickReplyButton{
						QuickReplyButton: &waProto.HydratedQuickReplyButton{
							DisplayText: &text,
							Id:          proto.String(idtext),
						},
					},
				})
			case "url":
				text := item.DisplayText
				url := item.Url
				buttons = append(buttons, &waProto.HydratedTemplateButton{
					HydratedButton: &waProto.HydratedTemplateButton_UrlButton{
						UrlButton: &waProto.HydratedURLButton{
							DisplayText: &text,
							Url:         &url,
						},
					},
				})
			case "call":
				text := item.DisplayText
				phonenumber := item.PhoneNumber
				buttons = append(buttons, &waProto.HydratedTemplateButton{
					HydratedButton: &waProto.HydratedTemplateButton_CallButton{
						CallButton: &waProto.HydratedCallButton{
							DisplayText: &text,
							PhoneNumber: &phonenumber,
						},
					},
				})
			default:
				text := item.DisplayText
				buttons = append(buttons, &waProto.HydratedTemplateButton{
					HydratedButton: &waProto.HydratedTemplateButton_QuickReplyButton{
						QuickReplyButton: &waProto.HydratedQuickReplyButton{
							DisplayText: &text,
							Id:          proto.String(string(id)),
						},
					},
				})
			}
			id++
		}

		msg := &waProto.Message{TemplateMessage: &waProto.TemplateMessage{
			HydratedTemplate: &waProto.HydratedFourRowTemplate{
				HydratedContentText: proto.String(t.Content),
				HydratedFooterText:  proto.String(t.Footer),
				HydratedButtons:     buttons,
				TemplateId:          proto.String("1"),
			},
		},
		}

		resp, err = clientPointer[userid].SendMessage(context.Background(),recipient, msg, whatsmeow.SendRequestExtra{ID: msgid})
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Message sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}
*/
// checks if users/phones are on Whatsapp
func (s *server) CheckUser() http.HandlerFunc {

	type checkUserStruct struct {
		Phone []string
	}

	type User struct {
		Query        string
		IsInWhatsapp bool
		JID          string
		VerifiedName string
	}

	type UserCollection struct {
		Users []User
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t checkUserStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if len(t.Phone) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		resp, err := clientPointer[userid].IsOnWhatsApp(t.Phone)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to check if users are on WhatsApp: %s", err)))
			return
		}

		uc := new(UserCollection)
		for _, item := range resp {
			if item.VerifiedName != nil {
				var msg = User{Query: item.Query, IsInWhatsapp: item.IsIn, JID: fmt.Sprintf("%s", item.JID), VerifiedName: item.VerifiedName.Details.GetVerifiedName()}
				uc.Users = append(uc.Users, msg)
			} else {
				var msg = User{Query: item.Query, IsInWhatsapp: item.IsIn, JID: fmt.Sprintf("%s", item.JID), VerifiedName: ""}
				uc.Users = append(uc.Users, msg)
			}
		}
		responseJson, err := json.Marshal(uc)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Gets user information
func (s *server) GetUser() http.HandlerFunc {

	type checkUserStruct struct {
		Phone []string
	}

	type UserCollection struct {
		Users map[types.JID]types.UserInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t checkUserStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if len(t.Phone) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		var jids []types.JID
		for _, arg := range t.Phone {
			jid, err := types.ParseJID(arg)
			if err != nil {
				return
			}
			jids = append(jids, jid)
		}
		resp, err := clientPointer[userid].GetUserInfo(jids)

		if err != nil {
			msg := fmt.Sprintf("Failed to get user info: %v", err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		uc := new(UserCollection)
		uc.Users = make(map[types.JID]types.UserInfo)

		for jid, info := range resp {
			uc.Users[jid] = info
		}

		responseJson, err := json.Marshal(uc)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

func (s *server) SendPresence() http.HandlerFunc {

	type PresenceRequest struct {
		Type string `json:"type" form:"type"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var pre PresenceRequest
		err := decoder.Decode(&pre)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		var presence types.Presence

		switch pre.Type {
		case "available":
			presence = types.PresenceAvailable
		case "unavailable":
			presence = types.PresenceUnavailable
		default:
			s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid presence type. Allowed values: 'available', 'unavailable'"))
			return
		}

		log.Info().Str("presence", pre.Type).Msg("Your global presence status")

		err = clientPointer[userid].SendPresence(presence)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failure sending presence to Whatsapp servers"))
			return
		}

		response := map[string]interface{}{"Details": "Presence set successfuly"}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return

	}
}

// Gets avatar info for user
func (s *server) GetAvatar() http.HandlerFunc {

	type getAvatarStruct struct {
		Phone   string
		Preview bool
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t getAvatarStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if len(t.Phone) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		jid, ok := parseJID(t.Phone)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Phone"))
			return
		}

		var pic *types.ProfilePictureInfo

		existingID := ""
		pic, err = clientPointer[userid].GetProfilePictureInfo(jid, &whatsmeow.GetProfilePictureParams{
			Preview:    t.Preview,
			ExistingID: existingID,
		})
		if err != nil {
			msg := fmt.Sprintf("Failed to get avatar: %v", err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
			return
		}

		if pic == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No avatar found"))
			return
		}

		log.Info().Str("id", pic.ID).Str("url", pic.URL).Msg("Got avatar")

		responseJson, err := json.Marshal(pic)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Gets all contacts
func (s *server) GetContacts() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		result := map[types.JID]types.ContactInfo{}
		result, err := clientPointer[userid].Store.Contacts.GetAllContacts(r.Context())
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
			return
		}

		responseJson, err := json.Marshal(result)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Sets Chat Presence (typing/paused/recording audio)
func (s *server) ChatPresence() http.HandlerFunc {

	type chatPresenceStruct struct {
		Phone string
		State string
		Media types.ChatPresenceMedia
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t chatPresenceStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if len(t.Phone) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone in Payload"))
			return
		}

		if len(t.State) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing State in Payload"))
			return
		}

		jid, ok := parseJID(t.Phone)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Phone"))
			return
		}

		err = clientPointer[userid].SendChatPresence(jid, types.ChatPresence(t.State), types.ChatPresenceMedia(t.Media))
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failure sending chat presence to Whatsapp servers"))
			return
		}

		response := map[string]interface{}{"Details": "Chat presence set successfuly"}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Downloads Image and returns base64 representation
func (s *server) DownloadImage() http.HandlerFunc {

	type downloadImageStruct struct {
		Url           string
		DirectPath    string
		MediaKey      []byte
		Mimetype      string
		FileEncSHA256 []byte
		FileSHA256    []byte
		FileLength    uint64
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		mimetype := ""
		var imgdata []byte

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		// check/creates user directory for files
		userDirectory := filepath.Join(s.exPath, "files", "user_"+txtid)
		_, err := os.Stat(userDirectory)
		if os.IsNotExist(err) {
			errDir := os.MkdirAll(userDirectory, 0751)
			if errDir != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not create user directory (%s)", userDirectory)))
				return
			}
		}

		decoder := json.NewDecoder(r.Body)
		var t downloadImageStruct
		err = decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		msg := &waProto.Message{ImageMessage: &waProto.ImageMessage{
			URL:           proto.String(t.Url),
			DirectPath:    proto.String(t.DirectPath),
			MediaKey:      t.MediaKey,
			Mimetype:      proto.String(t.Mimetype),
			FileEncSHA256: t.FileEncSHA256,
			FileSHA256:    t.FileSHA256,
			FileLength:    &t.FileLength,
		}}

		img := msg.GetImageMessage()

		if img != nil {
			imgdata, err = clientPointer[userid].Download(r.Context(), img)
			if err != nil {
				log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to download image")
				msg := fmt.Sprintf("Failed to download image %v", err)
				s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
				return
			}
			mimetype = img.GetMimetype()
		}

		dataURL := dataurl.New(imgdata, mimetype)
		response := map[string]interface{}{"Mimetype": mimetype, "Data": dataURL.String()}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Downloads Document and returns base64 representation
func (s *server) DownloadDocument() http.HandlerFunc {

	type downloadDocumentStruct struct {
		Url           string
		DirectPath    string
		MediaKey      []byte
		Mimetype      string
		FileEncSHA256 []byte
		FileSHA256    []byte
		FileLength    uint64
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		mimetype := ""
		var docdata []byte

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		// check/creates user directory for files
		userDirectory := filepath.Join(s.exPath, "files", "user_"+txtid)
		_, err := os.Stat(userDirectory)
		if os.IsNotExist(err) {
			errDir := os.MkdirAll(userDirectory, 0751)
			if errDir != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not create user directory (%s)", userDirectory)))
				return
			}
		}

		decoder := json.NewDecoder(r.Body)
		var t downloadDocumentStruct
		err = decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		msg := &waProto.Message{DocumentMessage: &waProto.DocumentMessage{
			URL:           proto.String(t.Url),
			DirectPath:    proto.String(t.DirectPath),
			MediaKey:      t.MediaKey,
			Mimetype:      proto.String(t.Mimetype),
			FileEncSHA256: t.FileEncSHA256,
			FileSHA256:    t.FileSHA256,
			FileLength:    &t.FileLength,
		}}

		doc := msg.GetDocumentMessage()

		if doc != nil {
			docdata, err = clientPointer[userid].Download(r.Context(), doc)
			if err != nil {
				log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to download document")
				msg := fmt.Sprintf("Failed to download document %v", err)
				s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
				return
			}
			mimetype = doc.GetMimetype()
		}

		dataURL := dataurl.New(docdata, mimetype)
		response := map[string]interface{}{"Mimetype": mimetype, "Data": dataURL.String()}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Downloads Video and returns base64 representation
func (s *server) DownloadVideo() http.HandlerFunc {

	type downloadVideoStruct struct {
		Url           string
		DirectPath    string
		MediaKey      []byte
		Mimetype      string
		FileEncSHA256 []byte
		FileSHA256    []byte
		FileLength    uint64
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		mimetype := ""
		var docdata []byte

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		// check/creates user directory for files
		userDirectory := filepath.Join(s.exPath, "files", "user_"+txtid)
		_, err := os.Stat(userDirectory)
		if os.IsNotExist(err) {
			errDir := os.MkdirAll(userDirectory, 0751)
			if errDir != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not create user directory (%s)", userDirectory)))
				return
			}
		}

		decoder := json.NewDecoder(r.Body)
		var t downloadVideoStruct
		err = decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		msg := &waProto.Message{VideoMessage: &waProto.VideoMessage{
			URL:           proto.String(t.Url),
			DirectPath:    proto.String(t.DirectPath),
			MediaKey:      t.MediaKey,
			Mimetype:      proto.String(t.Mimetype),
			FileEncSHA256: t.FileEncSHA256,
			FileSHA256:    t.FileSHA256,
			FileLength:    &t.FileLength,
		}}

		doc := msg.GetVideoMessage()

		if doc != nil {
			docdata, err = clientPointer[userid].Download(r.Context(), doc)
			if err != nil {
				log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to download video")
				msg := fmt.Sprintf("Failed to download video %v", err)
				s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
				return
			}
			mimetype = doc.GetMimetype()
		}

		dataURL := dataurl.New(docdata, mimetype)
		response := map[string]interface{}{"Mimetype": mimetype, "Data": dataURL.String()}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Downloads Audio and returns base64 representation
func (s *server) DownloadAudio() http.HandlerFunc {

	type downloadAudioStruct struct {
		Url           string
		DirectPath    string
		MediaKey      []byte
		Mimetype      string
		FileEncSHA256 []byte
		FileSHA256    []byte
		FileLength    uint64
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		mimetype := ""
		var docdata []byte

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		// check/creates user directory for files
		userDirectory := filepath.Join(s.exPath, "files", "user_"+txtid)
		_, err := os.Stat(userDirectory)
		if os.IsNotExist(err) {
			errDir := os.MkdirAll(userDirectory, 0751)
			if errDir != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Could not create user directory (%s)", userDirectory)))
				return
			}
		}

		decoder := json.NewDecoder(r.Body)
		var t downloadAudioStruct
		err = decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		msg := &waProto.Message{AudioMessage: &waProto.AudioMessage{
			URL:           proto.String(t.Url),
			DirectPath:    proto.String(t.DirectPath),
			MediaKey:      t.MediaKey,
			Mimetype:      proto.String(t.Mimetype),
			FileEncSHA256: t.FileEncSHA256,
			FileSHA256:    t.FileSHA256,
			FileLength:    &t.FileLength,
		}}

		doc := msg.GetAudioMessage()

		if doc != nil {
			docdata, err = clientPointer[userid].Download(r.Context(), doc)
			if err != nil {
				log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to download audio")
				msg := fmt.Sprintf("Failed to download audio %v", err)
				s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
				return
			}
			mimetype = doc.GetMimetype()
		}

		dataURL := dataurl.New(docdata, mimetype)
		response := map[string]interface{}{"Mimetype": mimetype, "Data": dataURL.String()}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// Edit
func (s *server) Edit() http.HandlerFunc {

	type textStruct struct {
		Chat    string
		Phone   string
		Id      string
		NewText string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t textStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Chat == "" || t.Phone == "" || t.Id == "" || t.NewText == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Chat, Phone, Id, or NewText in Payload"))
			return
		}

		// recipient, ok := parseJID(t.Phone)
		chat, ok := parseJID(t.Chat)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		fromMe := strings.HasPrefix(t.Id, "me:")
		msgid := t.Id
		if fromMe {
			msgid = t.Id[len("me:"):]
		}

		// Construindo a edição usando BuildEdit
		msg := clientPointer[userid].BuildEdit(chat, types.MessageID(msgid), &waProto.Message{
			Conversation: proto.String(t.NewText),
		})

		// Enviando a mensagem de edição
		resp, err := clientPointer[userid].SendMessage(r.Context(), chat, msg)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error editing message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Edit sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Revoke
func (s *server) Revoke() http.HandlerFunc {

	type textStruct struct {
		Chat  string
		Phone string
		Id    string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t textStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Chat == "" || t.Phone == "" || t.Id == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Chat, Phone, or Id in Payload"))
			return
		}

		recipient, ok := parseJID(t.Phone)
		chat, ok := parseJID(t.Chat)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		fromMe := strings.HasPrefix(t.Id, "me:")
		msgid := t.Id
		if fromMe {
			msgid = t.Id[len("me:"):]
		}

		// Define o `sender` para o BuildRevoke
		var sender types.JID
		if fromMe {
			sender = types.EmptyJID // Revogando uma mensagem enviada por você
		} else {
			sender = recipient // Revogando uma mensagem de outro usuário
		}

		// Construindo a revogação usando BuildRevoke
		msg := clientPointer[userid].BuildRevoke(chat, sender, types.MessageID(msgid))

		// Enviando a mensagem de revogação
		resp, err := clientPointer[userid].SendMessage(r.Context(), chat, msg)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error revoking message: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Revoke sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// React
func (s *server) React() http.HandlerFunc {

	type reactionStruct struct {
		Chat     string
		Phone    string
		Id       string
		Reaction string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t reactionStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Chat == "" || t.Phone == "" || t.Id == "" || t.Reaction == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Chat, Phone, Id, or Reaction in Payload"))
			return
		}

		recipient, ok := parseJID(t.Phone)
		chat, ok := parseJID(t.Chat)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		fromMe := strings.HasPrefix(t.Id, "me:")
		msgid := t.Id
		if fromMe {
			msgid = t.Id[len("me:"):]
		}

		// Define o `sender` para o BuildReaction
		var sender types.JID
		if fromMe {
			sender = types.EmptyJID // Reagindo a uma mensagem enviada por você
		} else {
			sender = recipient // Reagindo a uma mensagem de outro usuário
		}

		// Construindo a reação usando BuildReaction
		msg := clientPointer[userid].BuildReaction(chat, sender, types.MessageID(msgid), t.Reaction)

		// Enviando a mensagem de reação
		resp, err := clientPointer[userid].SendMessage(r.Context(), chat, msg)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending reaction: %v", err)))
			return
		}

		log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Reaction sent")
		response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// React
// func (s *server) React() http.HandlerFunc {

// 	type textStruct struct {
// 		Chat  string
// 		Phone string
// 		Body  string
// 		Id    string
// 	}

// 	return func(w http.ResponseWriter, r *http.Request) {

// 		txtid := r.Context().Value("userinfo").(Values).Get("Id")
// 		userid, _ := strconv.Atoi(txtid)

// 		if clientPointer[userid] == nil {
// 			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
// 			return
// 		}

// 		decoder := json.NewDecoder(r.Body)
// 		var t textStruct
// 		err := decoder.Decode(&t)
// 		if err != nil {
// 			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
// 			return
// 		}

// 		if t.Chat == "" || t.Phone == "" || t.Body == "" || t.Id == "" {
// 			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Phone, Body, or Id in Payload"))
// 			return
// 		}

// 		recipient, ok := parseJID(t.Phone)
// 		if !ok {
// 			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse recipient JID"))
// 			return
// 		}

// 		chat, ok := parseJID(t.Chat)
// 		if !ok {
// 			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse chat JID"))
// 			return
// 		}

// 		// Defina `fromMe` para identificar se a mensagem é enviada por você
// 		fromMe := strings.HasPrefix(t.Id, "me:")
// 		msgid := t.Id
// 		if fromMe {
// 			msgid = t.Id[len("me:"):]
// 		}

// 		reaction := t.Body
// 		if reaction == "remove" {
// 			reaction = ""
// 		}

// 		// Ajuste `chat` e `recipient` com base em `fromMe`
// 		if fromMe {
// 			// Mensagem enviada por você
// 			msg := clientPointer[userid].BuildReaction(chat, recipient, msgid, reaction)
// 			resp, err := clientPointer[userid].SendMessage(context.Background(), recipient, msg)
// 			if err != nil {
// 				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
// 				return
// 			}
// 			// Registro e resposta
// 			log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Reaction sent")
// 			response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
// 			responseJson, err := json.Marshal(response)
// 			if err != nil {
// 				s.Respond(w, r, http.StatusInternalServerError, err)
// 			} else {
// 				s.Respond(w, r, http.StatusOK, string(responseJson))
// 			}
// 		} else {
// 			// Mensagem recebida
// 			msg := clientPointer[userid].BuildReaction(recipient, chat, msgid, reaction)
// 			resp, err := clientPointer[userid].SendMessage(context.Background(), recipient, msg)
// 			if err != nil {
// 				s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("Error sending message: %v", err)))
// 				return
// 			}
// 			// Registro e resposta
// 			log.Info().Str("timestamp", fmt.Sprintf("%d", resp.Timestamp)).Str("id", msgid).Msg("Reaction sent")
// 			response := map[string]interface{}{"Details": "Sent", "Timestamp": resp.Timestamp, "Id": msgid}
// 			responseJson, err := json.Marshal(response)
// 			if err != nil {
// 				s.Respond(w, r, http.StatusInternalServerError, err)
// 			} else {
// 				s.Respond(w, r, http.StatusOK, string(responseJson))
// 			}
// 		}

// 		return
// 	}
// }

// Mark messages as read
func (s *server) MarkRead() http.HandlerFunc {

	type markReadStruct struct {
		Id     []string
		Chat   types.JID
		Sender types.JID
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t markReadStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		if t.Chat.String() == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Chat in Payload"))
			return
		}

		if len(t.Id) < 1 {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Id in Payload"))
			return
		}

		err = clientPointer[userid].MarkRead(t.Id, time.Now(), t.Chat, t.Sender)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("Failure marking messages as read"))
			return
		}

		response := map[string]interface{}{"Details": "Message(s) marked as read"}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
		return
	}
}

// List groups
func (s *server) ListGroups() http.HandlerFunc {

	type GroupCollection struct {
		Groups []types.GroupInfo
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		resp, err := clientPointer[userid].GetJoinedGroups(r.Context())

		if err != nil {
			msg := fmt.Sprintf("Failed to get group list: %v", err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		gc := new(GroupCollection)
		for _, info := range resp {
			gc.Groups = append(gc.Groups, *info)
		}

		responseJson, err := json.Marshal(gc)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Get group info
func (s *server) GetGroupInfo() http.HandlerFunc {

	type getGroupInfoStruct struct {
		GroupJID string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		// Get GroupJID from query parameter
		groupJID := r.URL.Query().Get("groupJID")
		if groupJID == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing groupJID parameter"))
			return
		}

		group, ok := parseJID(groupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		resp, err := clientPointer[userid].GetGroupInfo(group)

		if err != nil {
			msg := fmt.Sprintf("Failed to get group info: %v", err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		responseJson, err := json.Marshal(resp)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Get group invite link
func (s *server) GetGroupInviteLink() http.HandlerFunc {

	type getGroupInfoStruct struct {
		GroupJID string
		Reset    bool
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		// Get GroupJID from query parameter
		groupJID := r.URL.Query().Get("groupJID")
		if groupJID == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing groupJID parameter"))
			return
		}

		// Get reset parameter
		resetParam := r.URL.Query().Get("reset")
		reset := false
		if resetParam != "" {
			var err error
			reset, err = strconv.ParseBool(resetParam)
			if err != nil {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Invalid reset parameter, must be true or false"))
				return
			}
		}

		group, ok := parseJID(groupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		resp, err := clientPointer[userid].GetGroupInviteLink(group, reset)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to get group invite link")
			msg := fmt.Sprintf("Failed to get group invite link: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"InviteLink": resp}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Set group photo
func (s *server) SetGroupPhoto() http.HandlerFunc {

	type setGroupPhotoStruct struct {
		GroupJID string
		Image    string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t setGroupPhotoStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		if t.Image == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Image in Payload"))
			return
		}

		var filedata []byte

		if t.Image[0:13] == "data:image/jp" {
			dataURL, err := dataurl.DecodeString(t.Image)
			if err != nil {
				s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode base64 encoded data from payload"))
				return
			} else {
				filedata = dataURL.Data
			}
		} else {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Image data should start with \"data:image/jpeg;base64,\""))
			return
		}

		picture_id, err := clientPointer[userid].SetGroupPhoto(group, filedata)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to set group photo")
			msg := fmt.Sprintf("Failed to set group photo: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group Photo set successfully", "PictureID": picture_id}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// Set group name
func (s *server) SetGroupName() http.HandlerFunc {

	type setGroupNameStruct struct {
		GroupJID string
		Name     string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t setGroupNameStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not decode Payload"))
			return
		}

		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Could not parse Group JID"))
			return
		}

		if t.Name == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("Missing Name in Payload"))
			return
		}

		err = clientPointer[userid].SetGroupName(group, t.Name)

		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Failed to set group name")
			msg := fmt.Sprintf("Failed to set group name: %v", err)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		response := map[string]interface{}{"Details": "Group Name set successfully"}
		responseJson, err := json.Marshal(response)

		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// List newsletters
func (s *server) ListNewsletter() http.HandlerFunc {

	type NewsletterCollection struct {
		Newsletter []types.NewsletterMetadata
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		if clientPointer[userid] == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("No session"))
			return
		}

		resp, err := clientPointer[userid].GetSubscribedNewsletters()

		if err != nil {
			msg := fmt.Sprintf("Failed to get newsletter list: %v", err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, msg)
			return
		}

		gc := new(NewsletterCollection)
		for _, info := range resp {
			gc.Newsletter = append(gc.Newsletter, *info)
		}

		responseJson, err := json.Marshal(gc)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}

		return
	}
}

// ListUsers retorna a lista de instâncias de WhatsApp associadas ao usuário autenticado.
// A função foi refatorada para suportar multi-tenancy.
func (s *server) ListUsers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Extrair o supabase_user_id do contexto da requisição.
		// Este valor foi injetado pelo nosso jwtMiddleware.
		supabaseUserID, ok := r.Context().Value("supabase_user_id").(string)
		if !ok || supabaseUserID == "" {
			// Se não encontrarmos o ID, algo está muito errado (o middleware deveria ter bloqueado).
			s.Respond(w, r, http.StatusInternalServerError, errors.New("não foi possível identificar o usuário na requisição"))
			return
		}

		// 2. Chamar a função do repositório para buscar as instâncias do usuário.
		// Note que não estamos mais usando s.db.Select diretamente no handler.
		// A lógica de banco de dados está agora encapsulada no repositório.
		repo := repository.NewPostgresRepository(s.db)
		instances, err := repo.GetInstancesBySupabaseID(supabaseUserID)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, fmt.Errorf("erro ao buscar instâncias: %w", err))
			return
		}

		// 3. Retornar a lista de instâncias em formato JSON.
		s.Respond(w, r, http.StatusOK, instances)
	}
}

// AddInstance cria uma nova instância de WhatsApp para o usuário autenticado.
func (s *server) AddInstance() http.HandlerFunc {
	// A struct define o que esperamos receber no corpo da requisição JSON.
	// Apenas o nome da instância é necessário.
	type addInstanceRequest struct {
		Name string `json:"name"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Extrair o supabase_user_id do contexto.
		supabaseUserID, ok := r.Context().Value("supabase_user_id").(string)
		if !ok || supabaseUserID == "" {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("não foi possível identificar o usuário na requisição"))
			return
		}

		// 2. Decodificar o corpo da requisição para obter o nome da nova instância.
		var req addInstanceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("corpo da requisição inválido"))
			return
		}
		if req.Name == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("o campo 'name' é obrigatório"))
			return
		}

		// 3. Chamar a função do repositório para criar a instância no banco de dados.
		repo := repository.NewPostgresRepository(s.db)
		newInstance, err := repo.AddInstance(req.Name, supabaseUserID)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, fmt.Errorf("erro ao criar instância: %w", err))
			return
		}

		// 4. Retornar a instância recém-criada como resposta.
		s.Respond(w, r, http.StatusCreated, newInstance)
	}
}

// DeleteInstance remove uma instância de WhatsApp pertencente ao usuário autenticado.
func (s *server) DeleteInstance() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Extrair o supabase_user_id do contexto.
		supabaseUserID, ok := r.Context().Value("supabase_user_id").(string)
		if !ok || supabaseUserID == "" {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("não foi possível identificar o usuário na requisição"))
			return
		}

		// 2. Extrair o ID da instância do URL da requisição.
		vars := mux.Vars(r)
		instanceIDStr, ok := vars["id"]
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("ID da instância não fornecido na URL"))
			return
		}
		instanceID, err := strconv.Atoi(instanceIDStr)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("ID da instância inválido"))
			return
		}

		// 3. Chamar a função do repositório para deletar a instância.
		repo := repository.NewPostgresRepository(s.db)
		err = repo.DeleteInstance(instanceID, supabaseUserID)
		if err != nil {
			// O repositório retorna um erro específico se a instância não for encontrada ou não pertencer ao usuário.
			if err.Error() == "instância não encontrada ou não pertence ao usuário" {
				s.Respond(w, r, http.StatusNotFound, err)
			} else {
				s.Respond(w, r, http.StatusInternalServerError, fmt.Errorf("erro ao deletar instância: %w", err))
			}
			return
		}

		// Limpar o cache para remover informações da instância deletada.
		userinfocache.Flush()

		// 4. Retornar uma resposta de sucesso.
		response := map[string]interface{}{"details": "Instância deletada com sucesso"}
		jsonResponse, _ := json.Marshal(response)
		s.Respond(w, r, http.StatusOK, string(jsonResponse))
	}
}

// Writes JSON response to API clients
func (s *server) Respond(w http.ResponseWriter, r *http.Request, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	dataenvelope := map[string]interface{}{"code": status}
	if err, ok := data.(error); ok {
		dataenvelope["error"] = err.Error()
		dataenvelope["success"] = false
	} else {
		mydata := make(map[string]interface{})
		err = json.Unmarshal([]byte(data.(string)), &mydata)
		if err != nil {
			log.Error().Str("error", fmt.Sprintf("%v", err)).Msg("Error unmarshalling JSON")
		}
		dataenvelope["data"] = mydata
		dataenvelope["success"] = true
	}
	data = dataenvelope

	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic("respond: " + err.Error())
	}
}

func validateMessageFields(phone string, stanzaid *string, participant *string) (types.JID, error) {

	recipient, ok := parseJID(phone)
	if !ok {
		return types.NewJID("", types.DefaultUserServer), errors.New("Could not parse Phone")
	}

	if stanzaid != nil {
		if participant == nil {
			return types.NewJID("", types.DefaultUserServer), errors.New("Missing Participant in ContextInfo")
		}
	}

	if participant != nil {
		if stanzaid == nil {
			return types.NewJID("", types.DefaultUserServer), errors.New("Missing StanzaID in ContextInfo")
		}
	}

	return recipient, nil
}

func contains(slice []string, item string) bool {
	for _, value := range slice {
		if value == item {
			return true
		}
	}
	return false
}

func (s *server) SetProxy() http.HandlerFunc {
	type proxyStruct struct {
		ProxyURL string `json:"proxy_url"` // Format: "socks5://user:pass@host:port" or "http://host:port"
		Enable   bool   `json:"enable"`    // Whether to enable or disable proxy
	}

	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")
		userid, _ := strconv.Atoi(txtid)

		log.Info().Str("txtid", txtid).Int("userid", userid).Msg("SetProxy: User ID extracted")

		// Check if client exists and is connected
		if clientPointer[userid] != nil && clientPointer[userid].IsConnected() {
			s.Respond(w, r, http.StatusBadRequest, errors.New("cannot set proxy while connected. Please disconnect first"))
			return
		}

		decoder := json.NewDecoder(r.Body)
		var t proxyStruct
		err := decoder.Decode(&t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode payload"))
			return
		}

		// If enable is false, remove proxy configuration
		if !t.Enable {
			_, err = s.db.Exec("UPDATE users SET proxy_url = NULL WHERE id = $1", userid)
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, errors.New("failed to remove proxy configuration"))
				return
			}

			response := map[string]interface{}{"Details": "Proxy disabled successfully"}
			responseJson, err := json.Marshal(response)
			if err != nil {
				s.Respond(w, r, http.StatusInternalServerError, err)
			} else {
				s.Respond(w, r, http.StatusOK, string(responseJson))
			}
			return
		}

		// Validate proxy URL
		log.Info().Str("proxy_url", t.ProxyURL).Bool("enable", t.Enable).Msg("SetProxy: Validating proxy URL")
		if t.ProxyURL == "" {
			log.Warn().Msg("SetProxy: Missing proxy_url in payload")
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing proxy_url in payload"))
			return
		}

		proxyURL, err := url.Parse(t.ProxyURL)
		if err != nil {
			log.Error().Err(err).Str("proxy_url", t.ProxyURL).Msg("SetProxy: Invalid proxy URL format")
			s.Respond(w, r, http.StatusBadRequest, errors.New("invalid proxy URL format"))
			return
		}

		log.Info().Str("scheme", proxyURL.Scheme).Msg("SetProxy: Parsed proxy URL scheme")
		// Only allow http and socks5 proxies
		if proxyURL.Scheme != "http" && proxyURL.Scheme != "socks5" {
			log.Warn().Str("scheme", proxyURL.Scheme).Msg("SetProxy: Unsupported proxy scheme")
			s.Respond(w, r, http.StatusBadRequest, errors.New("only HTTP and SOCKS5 proxies are supported"))
			return
		}

		// Store proxy configuration in database
		log.Info().Str("proxy_url", t.ProxyURL).Int("userid", userid).Msg("SetProxy: Saving proxy to database")
		result, err := s.db.Exec("UPDATE users SET proxy_url = $1 WHERE id = $2", t.ProxyURL, userid)
		if err != nil {
			log.Error().Err(err).Msg("SetProxy: Failed to save proxy configuration")
			s.Respond(w, r, http.StatusInternalServerError, errors.New("failed to save proxy configuration"))
			return
		}

		rowsAffected, _ := result.RowsAffected()
		log.Info().Int64("rows_affected", rowsAffected).Msg("SetProxy: Database update result")

		response := map[string]interface{}{
			"Details":  "Proxy configured successfully",
			"ProxyURL": t.ProxyURL,
		}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}

func (s *server) ValidateToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Warn().Msg("Token não fornecido")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Token não fornecido",
				"valid": false,
			})
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Remove o prefixo "Bearer " se existir
		token := strings.TrimPrefix(authHeader, "Bearer ")
		log.Info().Str("token_recebido", token).Str("token_esperado", *adminToken).Msg("Validando token")

		// Verifica se o token corresponde ao token administrativo
		if token != *adminToken {
			log.Warn().Str("token_recebido", token).Str("token_esperado", *adminToken).Msg("Token inválido")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Token inválido",
				"valid": false,
			})
			return
		}

		log.Info().Msg("Token válido")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": true,
		})
	}
}

// EditInstance atualiza os dados de uma instância pertencente ao usuário autenticado.
func (s *server) EditInstance() http.HandlerFunc {
	type editInstanceRequest struct {
		Name    string `json:"name"`
		Webhook string `json:"webhook"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Extrair IDs e verificar posse
		supabaseUserID, ok := r.Context().Value("supabase_user_id").(string)
		if !ok || supabaseUserID == "" {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("não foi possível identificar o usuário"))
			return
		}
		vars := mux.Vars(r)
		instanceID, err := strconv.Atoi(vars["id"])
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("ID da instância inválido"))
			return
		}

		// 2. Decodificar corpo da requisição
		var req editInstanceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("corpo da requisição inválido"))
			return
		}
		if req.Name == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("o campo 'name' é obrigatório"))
			return
		}

		// 3. Chamar repositório para atualizar
		repo := repository.NewPostgresRepository(s.db)
		updatedInstance, err := repo.UpdateInstance(instanceID, supabaseUserID, req.Name, req.Webhook)
		if err != nil {
			s.Respond(w, r, http.StatusNotFound, err) // Repo retorna erro de "não encontrado"
			return
		}

		// 4. Retornar a instância atualizada
		s.Respond(w, r, http.StatusOK, updatedInstance)
	}
}
