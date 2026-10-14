import { Controller, Get } from "@nestjs/common";
import { sql } from "drizzle-orm";
import { getDatabase } from "../db/context.js";
import { NoTransaction, Public } from "../platform/http.js";

@Controller("api")
@NoTransaction()
export class HealthController {
  /** Liveness and database readiness (ALB target-group health check). */
  @Get("health")
  @Public()
  async health() {
    await getDatabase().db.execute(sql`select 1`);
    return { status: "ok", product: "Threatready", data: "synthetic" };
  }
}
