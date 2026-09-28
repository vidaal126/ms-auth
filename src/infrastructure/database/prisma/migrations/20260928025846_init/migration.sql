-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "roles" TEXT[],
    "active" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "refresh_tokens" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "familyId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "replacedById" TEXT,

    CONSTRAINT "refresh_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "refresh_tokens_tokenHash_key" ON "refresh_tokens"("tokenHash");

-- CreateIndex
CREATE INDEX "refresh_tokens_familyId_idx" ON "refresh_tokens"("familyId");

-- CreateIndex
CREATE INDEX "refresh_tokens_userId_idx" ON "refresh_tokens"("userId");

-- AddForeignKey
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Prisma nao modela CHECK constraints: escritas a mao, espelhando o dominio.
-- roles vai no CHECK (e nao em SET NOT NULL) para nao divergir do modelo
-- Prisma de lista escalar.
ALTER TABLE "users"
  ADD CONSTRAINT "users_email_normalized" CHECK ("email" = lower(btrim("email")) AND char_length("email") BETWEEN 3 AND 254),
  ADD CONSTRAINT "users_roles_valid" CHECK (
    "roles" IS NOT NULL
    AND cardinality("roles") > 0
    AND "roles" <@ ARRAY['admin', 'operator']::TEXT[]
  ),
  ADD CONSTRAINT "users_updated_after_created" CHECK ("updatedAt" >= "createdAt");

ALTER TABLE "refresh_tokens"
  ADD CONSTRAINT "refresh_tokens_expires_after_created" CHECK ("expiresAt" > "createdAt"),
  ADD CONSTRAINT "refresh_tokens_revoked_after_created" CHECK ("revokedAt" IS NULL OR "revokedAt" >= "createdAt"),
  ADD CONSTRAINT "refresh_tokens_hash_format" CHECK ("tokenHash" ~ '^[0-9a-f]{64}$');
