
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// jwtMiddleware é o nosso "porteiro" de autenticação.
// Ele verifica o token JWT do Supabase em cada requisição.
func (s *server) jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Obter o cabeçalho de autorização da requisição.
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// Se não houver cabeçalho, a requisição não é permitida.
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// 2. O cabeçalho deve estar no formato "Bearer <token>".
		// Vamos separar a palavra "Bearer" do token em si.
		headerParts := strings.Split(authHeader, " ")
		if len(headerParts) != 2 || headerParts[0] != "Bearer" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := headerParts[1]

		// 3. Obter o segredo JWT que configuramos nas variáveis de ambiente.
		jwtSecret := os.Getenv("SUPABASE_JWT_SECRET")
		if jwtSecret == "" {
			// Se o segredo não estiver configurado no servidor, retornamos um erro interno.
			http.Error(w, "Server configuration error: JWT secret not set", http.StatusInternalServerError)
			return
		}

		// 4. Validar o token.
		// A biblioteca `jwt` fará a verificação da assinatura e da validade (expiração, etc).
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Verificamos se o método de assinatura do token é o esperado (HMAC).
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			// Se estiver tudo certo, retornamos o nosso segredo para a biblioteca fazer a validação.
			return []byte(jwtSecret), nil
		})

		if err != nil {
			// Se a validação falhar (token expirado, assinatura inválida, etc), bloqueamos a requisição.
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// 5. Se o token for válido, extraímos as informações (claims) de dentro dele.
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// O 'sub' claim em um JWT do Supabase contém o ID do usuário.
			sub, ok := claims["sub"].(string)
			if !ok {
				http.Error(w, "Invalid token: missing 'sub' claim", http.StatusUnauthorized)
				return
			}

			// Adicionamos o ID do usuário do Supabase ao contexto da requisição.
			// Isso permite que as próximas funções na cadeia (os handlers) saibam qual usuário está fazendo a requisição.
			ctx := context.WithValue(r.Context(), "supabase_user_id", sub)

			// 6. A requisição é válida! Deixamos ela passar para o próximo handler, agora com o contexto atualizado.
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		}
	})
}
