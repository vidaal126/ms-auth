import { ConfigService } from "@nestjs/config";
import type { ILogger } from "@common/logger/logger.interface";
import type { Env } from "@config/env";
import { RefreshToken } from "@domain/entities/refresh-token.entity";
import { InMemoryRefreshTokenRepository } from "../../test/auth.fakes";
import { RefreshTokenCleanupService } from "./refresh-token-cleanup.service";

const NOW = new Date("2026-09-28T12:00:00.000Z");
const HOUR_MS = 3_600_000;

class RecordingLogger implements ILogger {
  readonly logs: { message: string; context?: Record<string, unknown> }[] = [];
  readonly errors: { message: string; err: Error }[] = [];

  log(message: string, context?: Record<string, unknown>): void {
    this.logs.push({ message, context });
  }
  warn(): void {}
  error(message: string, err: Error): void {
    this.errors.push({ message, err });
  }
  debug(): void {}
}

function configWith(batchSize: number): ConfigService<Env, true> {
  return new ConfigService<Env, true>({
    REFRESH_TOKEN_CLEANUP_INTERVAL_MS: 60_000,
    REFRESH_TOKEN_RETENTION_SECONDS: 24 * 3600,
    REFRESH_TOKEN_CLEANUP_BATCH_SIZE: batchSize,
  });
}

// Token que vence `hoursFromNow` horas depois de NOW (negativo = ja vencido).
function token(familyId: string, hoursFromNow: number): RefreshToken {
  const expiresAt = new Date(NOW.getTime() + hoursFromNow * HOUR_MS);
  return RefreshToken.restore({
    id: `${familyId}-${hoursFromNow}`,
    userId: "user-1",
    familyId,
    tokenHash: `hash-${familyId}-${hoursFromNow}`,
    expiresAt,
    createdAt: new Date(expiresAt.getTime() - 7 * 24 * HOUR_MS),
    revokedAt: null,
    replacedById: null,
  });
}

describe("RefreshTokenCleanupService", () => {
  let repository: InMemoryRefreshTokenRepository;
  let logger: RecordingLogger;

  beforeEach(() => {
    repository = new InMemoryRefreshTokenRepository();
    logger = new RecordingLogger();
  });

  const seed = async (...tokens: RefreshToken[]): Promise<void> => {
    for (const t of tokens) await repository.create(t);
  };

  it("remove so familias vencidas ha mais que a retencao", async () => {
    await seed(
      token("velha", -48),
      token("velha", -30),
      token("recente", -2),
      token("vigente", 5),
      // Rotacionado ha muito, mas o sucessor ainda vale: fica para o reuso.
      token("rotacionada", -72),
      token("rotacionada", 10),
    );
    const service = new RefreshTokenCleanupService(repository, logger, configWith(100));

    await service.run(NOW);

    expect([...repository.rows.keys()].sort()).toEqual(
      ["recente--2", "rotacionada--72", "rotacionada-10", "vigente-5"].sort(),
    );
    expect(logger.logs).toEqual([
      { message: "Refresh tokens vencidos removidos", context: { deleted: 2, cutoff: "2026-09-27T12:00:00.000Z" } },
    ]);
  });

  it("apaga em lotes ate um lote vir incompleto", async () => {
    await seed(...["a", "b", "c", "d", "e"].map((family) => token(family, -48)));
    const spy = jest.spyOn(repository, "deleteExpiredFamilies");
    const service = new RefreshTokenCleanupService(repository, logger, configWith(2));

    await service.run(NOW);

    expect(repository.rows.size).toBe(0);
    expect(spy.mock.calls.map(([, limit]) => limit)).toEqual([2, 2, 2]);
  });

  it("sem nada para remover nao loga", async () => {
    await seed(token("vigente", 5));
    const service = new RefreshTokenCleanupService(repository, logger, configWith(100));

    await service.run(NOW);

    expect(repository.rows.size).toBe(1);
    expect(logger.logs).toEqual([]);
  });

  it("falha do banco e logada, nao propaga", async () => {
    jest.spyOn(repository, "deleteExpiredFamilies").mockRejectedValue(new Error("db fora"));
    const service = new RefreshTokenCleanupService(repository, logger, configWith(100));

    await expect(service.run(NOW)).resolves.toBeUndefined();

    expect(logger.errors).toHaveLength(1);
    expect(logger.errors[0]?.err.message).toBe("db fora");
  });

  it("depois do shutdown nao apaga mais lotes", async () => {
    await seed(token("velha", -48));
    const service = new RefreshTokenCleanupService(repository, logger, configWith(100));

    await service.onModuleDestroy();
    await service.run(NOW);

    expect(repository.rows.size).toBe(1);
  });

  it("agenda pelo intervalo e o shutdown espera a execucao em andamento", async () => {
    jest.useFakeTimers({ now: NOW });
    try {
      let release: () => void = () => undefined;
      const pending = new Promise<number>((resolve) => {
        release = (): void => {
          resolve(0);
        };
      });
      const spy = jest.spyOn(repository, "deleteExpiredFamilies").mockReturnValue(pending);
      const service = new RefreshTokenCleanupService(repository, logger, configWith(100));
      service.onModuleInit();

      jest.advanceTimersByTime(60_000);
      // Execucao anterior ainda em andamento: o tick seguinte nao empilha outra.
      jest.advanceTimersByTime(60_000);
      expect(spy).toHaveBeenCalledTimes(1);

      let destroyed = false;
      const destroy = service.onModuleDestroy().then((): void => {
        destroyed = true;
      });
      await Promise.resolve();
      expect(destroyed).toBe(false);

      release();
      await destroy;
      jest.advanceTimersByTime(60_000);
      expect(spy).toHaveBeenCalledTimes(1);
    } finally {
      jest.useRealTimers();
    }
  });
});
