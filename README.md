# ms-auth

Serviço de identidade da plataforma (NestJS, Prisma, PostgreSQL):

- usuários com roles (`admin`, `operator`);
- login com senha (argon2id), access token JWT RS256 de vida curta e refresh
  token opaco com rotação;
- JWKS público para o [ms-gateway](../ms-gateway/README.md) validar tokens
  sem chamar o ms-auth a cada request.

## Arquitetura

- `src/domain`: `User` (email normalizado, roles válidas), `RefreshToken`,
  política de senha e erros de domínio (401, 403, 404, 409, 422).
- `src/application`: use cases de sessão (`Login`, `RefreshSession`,
  `Logout`) e de usuário (`CreateUser`, `GetUser`, `BootstrapAdmin`), sem
  dependência de Nest. Os ports ficam em `application/ports/auth.ports.ts`:
  repositórios, `PasswordHasher`, `AccessTokenIssuer` e `RefreshTokenSecrets`.
- `src/infrastructure`: argon2, jose (JWT e JWKS), Prisma, HTTP, guard JWT e
  health.

### Tokens

| Token | Formato | Vida | Onde fica |
|---|---|---|---|
| access | JWT RS256: `sub`, `roles`, `iss`, `aud`, `iat`, `exp`, `jti`; header com `kid` | `ACCESS_TOKEN_TTL_SECONDS` (15 min) | só com o cliente |
| refresh | 256 bits aleatórios (base64url), opaco | `REFRESH_TOKEN_TTL_SECONDS` (7 dias) | o banco guarda só o sha256 |

- **Rotação**: cada refresh token vale uma vez. `POST /auth/refresh` revoga o
  atual e emite outro da mesma família, via compare-and-set em
  `refresh_tokens`.
- **Detecção de reuso**: apresentar um refresh token já rotacionado, ou perder
  a corrida de dois refresh simultâneos, revoga a família inteira. O usuário
  precisa fazer login de novo. Um token revogado por logout, ou pela revogação
  da família, não conta como reuso: recebe só 401 de token inválido
  (`replacedById` distingue os dois casos).
- **`kid`**: é o thumbprint RFC 7638 da chave pública. Ele só muda se a chave
  mudar, o que permite ao gateway manter o JWKS em cache.
- **Login**: email inexistente, senha errada e usuário inativo dão o mesmo 401.
  Quando o usuário não existe, a senha é comparada contra um hash fictício,
  para o tempo de resposta não revelar se o email existe.

## Como subir

Com a infraestrutura do [ms-platform](../ms-platform/README.md) no ar:

```bash
cp .env.example .env
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out signing-key.pem
yarn install
yarn prisma migrate deploy
yarn start
```

No compose, a chave é gerada uma vez por um job e fica em um volume.

## Variáveis de ambiente

Validadas com Zod no boot; env inválida impede a subida. Veja `.env.example`.

| Variável | Padrão | Descrição |
|---|---|---|
| `DATABASE_URL` | obrigatória | database `auth` |
| `AUTH_PRIVATE_KEY_FILE` / `AUTH_PRIVATE_KEY_PEM` | uma das duas | chave RSA PKCS#8 com pelo menos 2048 bits; o PEM aceita `\n` literal |
| `AUTH_ISSUER` / `AUTH_AUDIENCE` | `ms-auth` / `ms-platform` | claims validadas pelo gateway |
| `ACCESS_TOKEN_TTL_SECONDS` | 900 | de 60 a 3600 |
| `REFRESH_TOKEN_TTL_SECONDS` | 604800 | de 1 hora a 30 dias |
| `AUTH_BOOTSTRAP_ADMIN_EMAIL` / `_PASSWORD` | vazio | admin criado no boot, de forma idempotente |
| `THROTTLE_LOGIN_TTL_MS` / `_LIMIT` | 60000 / 10 | limite de login e refresh por IP |
| `THROTTLE_DEFAULT_TTL_MS` / `_LIMIT` | 60000 / 100 | demais rotas |

## API HTTP

| Método | Rota | Acesso | Descrição |
|---|---|---|---|
| `POST` | `/auth/login` | público | `{email, password}` retorna `{tokenType, accessToken, expiresIn, refreshToken, refreshExpiresIn}` |
| `POST` | `/auth/refresh` | público | `{refreshToken}` retorna um par novo; reuso revoga a sessão (401) |
| `POST` | `/auth/logout` | público | `{refreshToken}` retorna 204; idempotente |
| `POST` | `/users` | `admin` | `{email, password (12 a 128 caracteres), roles}` retorna o usuário, sem o hash |
| `GET` | `/users/me` | autenticado | dono do token |
| `GET` | `/.well-known/jwks.json` | público | chave pública (`Cache-Control: max-age=300`) |
| `GET` | `/health/live` e `/health/ready` | público | liveness; readiness verifica o banco |
| `GET` | `/metrics` | rede interna | Prometheus: HTTP por rota e `auth_session_events_total{event,outcome}` |

As respostas de token levam `Cache-Control: no-store`. O ms-auth valida o
próprio JWT nas rotas `/users`, em vez de confiar só no gateway.

## Testes

```bash
yarn lint && yarn typecheck
yarn test              # unitários: domínio, use cases, argon2, jose, env
yarn test:integration  # Postgres real (testcontainers)
```

## Limitações conhecidas

- **Uma chave de assinatura por vez.** Trocar a chave invalida os access tokens
  em circulação, que duram no máximo o TTL. Uma rotação sem essa janela exigiria
  publicar duas chaves no JWKS.
- **Access token não é revogável.** O logout revoga só o refresh; o access
  continua válido até expirar.
- **Tokens vencidos não são removidos.** Não há limpeza periódica de
  `refresh_tokens` expirados.
- **Sem desativação nem troca de senha pela API.** `active` existe no modelo,
  mas não há endpoint para mudá-lo.
- **Rate limit em memória, por réplica.**
