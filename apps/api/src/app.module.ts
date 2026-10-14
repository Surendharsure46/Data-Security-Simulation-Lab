/** Threatready API: one NestJS modular monolith. Each controller group maps to a bounded context. */
import { Module } from "@nestjs/common";
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from "@nestjs/core";
import { ThrottlerGuard, ThrottlerModule } from "@nestjs/throttler";
import { getConfig } from "./config.js";
import { AdminController } from "./modules/admin.controller.js";
import { AuthController } from "./modules/auth.controller.js";
import { EnvironmentController } from "./modules/environment.controller.js";
import { HealthController } from "./modules/health.controller.js";
import { InvestigationsController } from "./modules/investigations.controller.js";
import { CareerController, CurriculumController } from "./modules/journey.controller.js";
import { LabsController } from "./modules/labs.controller.js";
import { EngineeringController, PoliciesController } from "./modules/policies.controller.js";
import { SessionsController } from "./modules/sessions.controller.js";
import { ApiExceptionFilter, AuthGuard, RequestTransactionInterceptor } from "./platform/http.js";

export const CONTROLLERS = [
  HealthController, AuthController, CareerController, CurriculumController, SessionsController, EnvironmentController, PoliciesController,
  EngineeringController, InvestigationsController, LabsController, AdminController,
];

@Module({
  // Async factory: configuration is read when the app is created, not when this module is imported (a missing setting
  // must surface as a startup error, never as a failed import).
  imports: [ThrottlerModule.forRootAsync({ useFactory: () => ({ throttlers: [{ name: "api", ttl: 60_000, limit: getConfig().apiRateLimitPerMinute }] }) })],
  controllers: CONTROLLERS,
  providers: [
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: AuthGuard },
    { provide: APP_INTERCEPTOR, useClass: RequestTransactionInterceptor },
    { provide: APP_FILTER, useClass: ApiExceptionFilter },
  ],
})
export class AppModule {}
