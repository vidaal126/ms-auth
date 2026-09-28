import { Inject, Injectable, type OnApplicationBootstrap } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { type ILogger, LOGGER_TOKEN } from "@common/logger/logger.interface";
import { type Env, readEnv } from "@config/env";
import { BootstrapAdminUseCase } from "@application/use-cases/user.use-cases";

// Cria o primeiro admin a partir do env (se configurado). Falha aqui derruba
// o boot: um ambiente sem admin nao consegue cadastrar ninguem.
@Injectable()
export class BootstrapAdminService implements OnApplicationBootstrap {
  constructor(
    private readonly bootstrapAdmin: BootstrapAdminUseCase,
    private readonly config: ConfigService<Env, true>,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    const email = readEnv(this.config, "AUTH_BOOTSTRAP_ADMIN_EMAIL");
    const password = readEnv(this.config, "AUTH_BOOTSTRAP_ADMIN_PASSWORD");
    if (email === undefined || password === undefined) return;

    const outcome = await this.bootstrapAdmin.execute(email, password);
    this.logger.log("Admin inicial verificado", { email, outcome });
  }
}
