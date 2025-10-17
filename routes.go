package main

import (
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
)

type Middleware = alice.Constructor

func (s *server) routes() {

	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)

	var routerLog zerolog.Logger
	if *logType == "json" {
		routerLog = zerolog.New(os.Stdout).
			With().
			Timestamp().
			Str("role", filepath.Base(os.Args[0])).
			Str("host", *address).
			Logger()
	} else {
		output := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
			NoColor:    !*colorOutput,
		}
		routerLog = zerolog.New(output).
			With().
			Timestamp().
			Str("role", filepath.Base(os.Args[0])).
			Str("host", *address).
			Logger()
	}

	adminRoutes := s.router.PathPrefix("/admin").Subrouter()
	adminRoutes.Use(s.authadmin)
	// As rotas para listar e adicionar usuários foram movidas para /instances e agora são protegidas por JWT
	adminRoutes.Handle("/users/{id}", s.EditUser()).Methods("PUT")
	// A rota para deletar usuários foi movida para /instances/{id} e agora é protegida por JWT


	c := alice.New()
	c = c.Append(s.jwtMiddleware) // NOVO: Usando o middleware JWT do Supabase
	c = c.Append(hlog.NewHandler(routerLog))

	c = c.Append(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().
			Str("method", r.Method).
			Stringer("url", r.URL).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			// O "userid" agora pode vir do supabase_user_id ou de outra informação que escolhermos
			// Por enquanto, vamos deixar de logar o r.Context().Value("userinfo") para evitar pânico
			Msg("Got API Request")
	}))
	c = c.Append(hlog.RemoteAddrHandler("ip"))
	c = c.Append(hlog.UserAgentHandler("user_agent"))
	c = c.Append(hlog.RefererHandler("referer"))
	c = c.Append(hlog.RequestIDHandler("req_id", "Request-Id"))

	// Novas rotas de instâncias protegidas por JWT
	s.router.Handle("/instances", c.Then(s.ListUsers())).Methods("GET")
	s.router.Handle("/instances", c.Then(s.AddInstance())).Methods("POST")
	s.router.Handle("/instances/{id}", c.Then(s.DeleteInstance())).Methods("DELETE")


	s.router.Handle("/instances/{id}/connect", c.Then(s.Connect())).Methods("POST")
	s.router.Handle("/instances/{id}/disconnect", c.Then(s.Disconnect())).Methods("POST")
	s.router.Handle("/instances/{id}/logout", c.Then(s.Logout())).Methods("POST")
	s.router.Handle("/instances/{id}/status", c.Then(s.GetStatus())).Methods("GET")
	s.router.Handle("/instances/{id}/qr", c.Then(s.GetQR())).Methods("GET")
	s.router.Handle("/session/pairphone", c.Then(s.PairPhone())).Methods("POST")

	s.router.Handle("/webhook", c.Then(s.SetWebhook())).Methods("POST")
	s.router.Handle("/webhook", c.Then(s.GetWebhook())).Methods("GET")
	s.router.Handle("/webhook", c.Then(s.DeleteWebhook())).Methods("DELETE")     // Nova rota
	s.router.Handle("/webhook/update", c.Then(s.UpdateWebhook())).Methods("PUT") // Nova rota
	s.router.Handle("/session/proxy", c.Then(s.SetProxy())).Methods("POST")

	s.router.Handle("/chat/send/text", c.Then(s.SendMessage())).Methods("POST")
	s.router.Handle("/chat/send/image", c.Then(s.SendImage())).Methods("POST")
	s.router.Handle("/chat/send/audio", c.Then(s.SendAudio())).Methods("POST")
	s.router.Handle("/chat/send/document", c.Then(s.SendDocument())).Methods("POST")
	//	s.router.Handle("/chat/send/template", c.Then(s.SendTemplate())).Methods("POST")
	s.router.Handle("/chat/send/video", c.Then(s.SendVideo())).Methods("POST")
	s.router.Handle("/chat/send/sticker", c.Then(s.SendSticker())).Methods("POST")
	s.router.Handle("/chat/send/location", c.Then(s.SendLocation())).Methods("POST")
	s.router.Handle("/chat/send/contact", c.Then(s.SendContact())).Methods("POST")
	s.router.Handle("/chat/react", c.Then(s.React())).Methods("POST")
	s.router.Handle("/user/presence", c.Then(s.SendPresence())).Methods("POST")
	s.router.Handle("/chat/edit", c.Then(s.Edit())).Methods("POST")
	s.router.Handle("/chat/revoke", c.Then(s.Revoke())).Methods("POST")
	s.router.Handle("/chat/send/buttons", c.Then(s.SendButtons())).Methods("POST")
	s.router.Handle("/chat/send/list", c.Then(s.SendList())).Methods("POST")
	s.router.Handle("/chat/send/poll", c.Then(s.SendPoll())).Methods("POST")

	s.router.Handle("/user/info", c.Then(s.GetUser())).Methods("POST")
	s.router.Handle("/user/check", c.Then(s.CheckUser())).Methods("POST")
	s.router.Handle("/user/avatar", c.Then(s.GetAvatar())).Methods("POST")
	s.router.Handle("/user/contacts", c.Then(s.GetContacts())).Methods("GET")

	s.router.Handle("/chat/presence", c.Then(s.ChatPresence())).Methods("POST")
	s.router.Handle("/chat/markread", c.Then(s.MarkRead())).Methods("POST")
	s.router.Handle("/chat/downloadimage", c.Then(s.DownloadImage())).Methods("POST")
	s.router.Handle("/chat/downloadvideo", c.Then(s.DownloadVideo())).Methods("POST")
	s.router.Handle("/chat/downloadaudio", c.Then(s.DownloadAudio())).Methods("POST")
	s.router.Handle("/chat/downloaddocument", c.Then(s.DownloadDocument())).Methods("POST")

	s.router.Handle("/group/list", c.Then(s.ListGroups())).Methods("GET")
	s.router.Handle("/group/create", c.Then(s.CreateGroup())).Methods("POST")
	s.router.Handle("/group/info", c.Then(s.GetGroupInfo())).Methods("GET")
	s.router.Handle("/group/invitelink", c.Then(s.GetGroupInviteLink())).Methods("GET")
	s.router.Handle("/group/photo", c.Then(s.SetGroupPhoto())).Methods("POST")
	s.router.Handle("/group/photo/remove", c.Then(s.RemoveGroupPhoto())).Methods("POST")
	s.router.Handle("/group/name", c.Then(s.SetGroupName())).Methods("POST")
	s.router.Handle("/group/leave", c.Then(s.GroupLeave())).Methods("POST")
	s.router.Handle("/group/topic", c.Then(s.SetGroupTopic())).Methods("POST")
	s.router.Handle("/group/announce", c.Then(s.SetGroupAnnounce())).Methods("POST")
	s.router.Handle("/group/locked", c.Then(s.SetGroupLocked())).Methods("POST")
	s.router.Handle("/group/ephemeral", c.Then(s.SetDisappearingTimer())).Methods("POST")
	s.router.Handle("/group/join", c.Then(s.GroupJoin())).Methods("POST")
	s.router.Handle("/group/inviteinfo", c.Then(s.GetGroupInviteInfo())).Methods("POST")
	s.router.Handle("/group/updateparticipants", c.Then(s.UpdateGroupParticipants())).Methods("POST")
	s.router.Handle("/newsletter/list", c.Then(s.ListNewsletter())).Methods("GET")
	// s.router.Handle("/newsletters/info", c.Then(s.GetNewsletterInfo())).Methods("GET")

	// Rota pública para validação de token
	s.router.HandleFunc("/api/validate-token", s.ValidateToken()).Methods("GET")

	// Rota para arquivos estáticos deve ser a última
	s.router.PathPrefix("/").Handler(http.FileServer(http.Dir(exPath + "/static/")))
}
