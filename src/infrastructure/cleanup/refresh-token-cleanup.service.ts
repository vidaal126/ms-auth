import {
  Inject,
  Injectable,
  type OnModuleDestroy,
  type OnModuleInit,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { type ILogger, LOGGER_TOKEN } from "@common/logger/logger.interface";
import { type Env, readEnv } from "@config/env";
import { type IRefreshTokenRepository, REFRESH_TOKEN_REPOSITORY } from "@application/ports/auth.ports";

// Remove refresh tokens vencidos ha mais que a retencao, em lotes. Token
// vencido ja e rejeitado no refresh; a familia so sai quando nenhum token dela
// esta vigente, entao a deteccao de reuso nao perde nada. Rodar em varias
// replicas e seguro: o DELETE e idempotente.
@Injectable()
export class RefreshTokenCleanupService implements OnModuleInit, OnModuleDestroy {
  private readonly intervalMs: number;
  private readonly retentionMs: number;
  private readonly batchSize: number;
  private intervalHandle: NodeJS.Timeout | null = null;
  private currentRun: Promise<void> | null = null;
  private stopping = false;

  constructor(
    @Inject(REFRESH_TOKEN_REPOSITORY) private readonly refreshTokens: IRefreshTokenRepository,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    config: ConfigService<Env, true>,
  ) {
    this.intervalMs = readEnv(config, "REFRESH_TOKEN_CLEANUP_INTERVAL_MS");
    this.retentionMs = readEnv(config, "REFRESH_TOKEN_RETENTION_SECONDS") * 1000;
    this.batchSize = readEnv(config, "REFRESH_TOKEN_CLEANUP_BATCH_SIZE");
  }

  onModuleInit(): void {
    this.intervalHandle = setInterval((): void => {
      if (this.currentRun) return;
      // run nunca rejeita (erros sao logados dentro dele).
      this.currentRun = this.run().finally((): void => {
        this.currentRun = null;
      });
    }, this.intervalMs);
  }

  // Para entre lotes: o shutdown espera no maximo o lote em andamento.
  async onModuleDestroy(): Promise<void> {
    this.stopping = true;
    if (this.intervalHandle) clearInterval(this.intervalHandle);
    await this.currentRun;
  }

  async run(now: Date = new Date()): Promise<void> {
    const cutoff = new Date(now.getTime() - this.retentionMs);
    let deleted = 0;
    try {
      while (!this.stopping) {
        const batch = await this.refreshTokens.deleteExpiredFamilies(cutoff, this.batchSize);
        deleted += batch;
        if (batch < this.batchSize) break;
      }
    } catch (err) {
      this.logger.error(
        "Falha na limpeza de refresh tokens",
        err instanceof Error ? err : new Error(String(err)),
        { deleted },
      );
      return;
    }
    if (deleted > 0) {
      this.logger.log("Refresh tokens vencidos removidos", { deleted, cutoff: cutoff.toISOString() });
    }
  }
}
