# WuzAPI - Resumo do Projeto (Memória do Gemini)

## Visão Geral do Projeto
O WuzAPI é um gateway de API REST para o WhatsApp. Ele foi projetado para gerenciar sessões do WhatsApp, enviar/receber mensagens e interagir com contatos/grupos através de uma API RESTful, que é gerenciada por uma interface web.

## Tecnologias Utilizadas
*   **Backend:** Go (com a biblioteca `whatsmeow`)
*   **Frontend:** React/TypeScript
*   **Banco de Dados:** PostgreSQL
*   **Containerização:** Docker

## Objetivo Macro Atual
Transformar o WuzAPI em um backend multi-usuário para um SaaS (Software as a Service) de análise de conversas do WhatsApp.

## Integração Chave: Supabase
A principal etapa para alcançar o objetivo multi-usuário foi a integração do Supabase, visando gerenciar a autenticação de usuários e garantir que cada usuário possa acessar apenas suas próprias instâncias do WhatsApp.

## Status do Plano de Refatoração (Multi-Tenancy com Supabase)
De acordo com minha memória, o plano de refatoração para uma arquitetura multi-tenant com Supabase foi **concluído**. Todas as fases principais, tanto no backend (Go) quanto no frontend (React), foram finalizadas. O sistema agora possui autenticação de usuário via Supabase, rotas de API seguras e multi-tenant, e uma interface de usuário que reflete essa nova arquitetura de login.

## Problema Conhecido Atualmente
O código que foi recentemente enviado para o repositório GitHub (`Allansevero/metrisap.git`) possui um **erro de compilação** no backend.

*   **Erro:** `s.EditUser undefined (type *server has no field or method EditUser)`
*   **Localização:** `routes.go`, linha 49.
*   **Impacto:** Este erro impede que o backend seja compilado e executado corretamente, resultando em falhas na API (como o erro "404 page not found" observado anteriormente). A função `EditUser` está sendo chamada, mas não foi implementada no struct `server` ou em seus métodos.
