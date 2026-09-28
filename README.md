# ms-auth

> Plataforma: [ms-platform](https://github.com/vidaal126/ms-platform#readme) · [ms-gateway](https://github.com/vidaal126/ms-gateway#readme) · **ms-auth** · [ms-catalog](https://github.com/vidaal126/ms-catalog#readme) · [ms-transport](https://github.com/vidaal126/ms-transport#readme) · [ms-customer](https://github.com/vidaal126/ms-customer#readme) · [ms-sales-order](https://github.com/vidaal126/ms-sales-order#readme)

Serviço de identidade da plataforma (NestJS, Prisma, PostgreSQL):

- usuários com roles (`admin`, `operator`);
- login com senha (argon2id), access token JWT RS256 de vida curta e refresh
  token opaco com rotação;
- JWKS público para o [ms-gateway](https://github.com/vidaal126/ms-gateway#readme) validar tokens
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
- **Limpeza**: um job periódico apaga, em lotes, os refresh tokens de famílias
  cujo token mais novo venceu há mais que `REFRESH_TOKEN_RETENTION_SECONDS`.
  Token vencido já é rejeitado; enquanto a família tiver um token vigente, os
  rotacionados ficam, para a detecção de reuso continuar funcionando.
- **`kid`**: é o thumbprint RFC 7638 da chave pública. Ele só muda se a chave
  mudar, o que permite ao gateway manter o JWKS em cache.
- **Login**: email inexistente, senha errada e usuário inativo dão o mesmo 401.
  Quando o usuário não existe, a senha é comparada contra um hash fictício,
  para o tempo de resposta não revelar se o email existe.

## Como subir

Com a infraestrutura do [ms-platform](https://github.com/vidaal126/ms-platform#readme) no ar:

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
| `REFRESH_TOKEN_CLEANUP_INTERVAL_MS` | 3600000 | intervalo da limpeza de refresh tokens |
| `REFRESH_TOKEN_RETENTION_SECONDS` | 86400 | quanto tempo uma família vencida fica antes de ser apagada (até 90 dias) |
| `REFRESH_TOKEN_CLEANUP_BATCH_SIZE` | 1000 | linhas por DELETE (até 10000) |
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
- **Sem desativação nem troca de senha pela API.** `active` existe no modelo,
  mas não há endpoint para mudá-lo.
- **Rate limit em memória, por réplica.** O `trust proxy` confia em
  exatamente 1 salto (o ms-gateway, que anexa o IP do cliente ao
  `X-Forwarded-For`), então o limite conta por cliente e não pelo IP do
  gateway. Acessar o serviço direto, sem o gateway, permite escolher o IP
  contado via `X-Forwarded-For`.
