/**
 * Learning journey API (public welcome content, role choice, Levels 0-5, lab missions and level-up celebrations) and the
 * Learning Library (curriculum, knowledge checks, dashboard).
 */
import { Controller, Get, Param, Put } from "@nestjs/common";
import { AnswersIn, DemoClassifyIn, DemoScanIn, DemoTransferIn, MissionSubmitIn, PathwayIn, RetryIn, RoleChoiceIn } from "@threatready/contracts";
import { z } from "zod";
import { DomainError } from "../common/util.js";
import type { Principal } from "../db/context.js";
import * as career from "../domain/career.js";
import * as curriculum from "../domain/curriculum.js";
import { CurrentPrincipal, Permission, PERMISSIONS, PostCreated, PostOk, Public, ZBody } from "../platform/http.js";

const LevelParam = z.coerce.number().int().min(0).max(99);
const level = (raw: string) => {
  const r = LevelParam.safeParse(raw);
  if (!r.success) throw new DomainError("Level not found", 404);
  return r.data;
};
const IdNum = z.coerce.number().int().min(1).max(2_147_483_647);
const attemptId = (raw: string) => {
  const r = IdNum.safeParse(raw);
  if (!r.success) throw new DomainError("Lab attempt not found", 404);
  return r.data;
};

@Controller("api/career")
@Permission(PERMISSIONS.SELF)
export class CareerController {
  /** Welcome page, platform overview, roles and level outline. No authentication; contains nothing user-specific. */
  @Get("public")
  @Public()
  publicContent() {
    return career.publicContent();
  }

  @Get("profile")
  async profile(@CurrentPrincipal() p: Principal) {
    return career.profileOut(await career.getProfile(p.userId));
  }

  @Put("role")
  async role(@CurrentPrincipal() p: Principal, @ZBody(RoleChoiceIn) body: z.infer<typeof RoleChoiceIn>) {
    return career.profileOut(await career.chooseRole(p, body.role));
  }

  @Get("journey")
  journey(@CurrentPrincipal() p: Principal) {
    return career.journey(p);
  }

  @Get("levels/:level")
  level(@Param("level") lv: string, @CurrentPrincipal() p: Principal) {
    return career.levelDetail(p, level(lv));
  }

  @PostOk("levels/:level/read/:key")
  markRead(@Param("level") lv: string, @Param("key") key: string, @CurrentPrincipal() p: Principal) {
    return career.markRead(p, level(lv), key);
  }

  @PostOk("levels/:level/check")
  levelCheck(@Param("level") lv: string, @CurrentPrincipal() p: Principal, @ZBody(AnswersIn) body: z.infer<typeof AnswersIn>) {
    return career.answerLevelCheck(p, level(lv), body.answers);
  }

  // ------------------------------------------------------------------------- interactive demo lab

  @PostOk("demo/scan")
  demoScan(@CurrentPrincipal() p: Principal, @ZBody(DemoScanIn) body: z.infer<typeof DemoScanIn>) {
    return career.demoScan(p.userId, body.text);
  }

  @PostOk("demo/classify")
  demoClassify(@CurrentPrincipal() p: Principal, @ZBody(DemoClassifyIn) body: z.infer<typeof DemoClassifyIn>) {
    return career.demoClassify(p.userId, body.label);
  }

  @PostOk("demo/transfer")
  demoTransfer(@CurrentPrincipal() p: Principal, @ZBody(DemoTransferIn) body: z.infer<typeof DemoTransferIn>) {
    return career.demoTransfer(p.userId, body.destination);
  }

  // ------------------------------------------------------------------------- lab missions

  @Get("missions/:missionId")
  mission(@Param("missionId") missionId: string) {
    return career.missionPublic(missionId);
  }

  @PostCreated("missions/:missionId/start")
  async start(@Param("missionId") missionId: string, @CurrentPrincipal() p: Principal) {
    return career.attemptOut(p.userId, await career.startMission(p, missionId));
  }

  @Get("attempts/:attemptId")
  async attempt(@Param("attemptId") id: string, @CurrentPrincipal() p: Principal) {
    const a = await career.loadAttempt(p, attemptId(id), { write: false });
    return career.attemptOut(a.user_id, a);
  }

  @PostOk("attempts/:attemptId/understand")
  async understand(@Param("attemptId") id: string, @CurrentPrincipal() p: Principal, @ZBody(AnswersIn) body: z.infer<typeof AnswersIn>) {
    return career.answerUnderstanding(await career.loadAttempt(p, attemptId(id), { write: true }), body.answers);
  }

  @PostOk("attempts/:attemptId/submit")
  async submit(@Param("attemptId") id: string, @CurrentPrincipal() p: Principal, @ZBody(MissionSubmitIn) body: z.infer<typeof MissionSubmitIn>) {
    const a = await career.loadAttempt(p, attemptId(id), { write: true });
    await career.submitAttempt(p, a, body.explanation, body.cited_evidence);
    return career.attemptOut(p.userId, a);
  }

  @PostCreated("attempts/:attemptId/retry")
  async retry(@Param("attemptId") id: string, @CurrentPrincipal() p: Principal, @ZBody(RetryIn) body: z.infer<typeof RetryIn>) {
    const a = await career.loadAttempt(p, attemptId(id), { write: true });
    return career.attemptOut(p.userId, await career.retry(p, a, body.strategy));
  }

  // ------------------------------------------------------------------------- level-up celebration

  @Get("promotion")
  async promotion(@CurrentPrincipal() p: Principal) {
    return { pending: career.promotionOut(await career.getProfile(p.userId)) };
  }

  @PostOk("promotion/acknowledge")
  async acknowledge(@CurrentPrincipal() p: Principal) {
    const prof = await career.getProfile(p.userId);
    if (prof.pending_promotion === null) throw new DomainError("Nothing to acknowledge", 409);
    career.acknowledgePromotion(prof);
    return career.profileOut(prof);
  }
}

@Controller("api")
@Permission(PERMISSIONS.SELF)
export class CurriculumController {
  @Get("curriculum")
  curriculum(@CurrentPrincipal() p: Principal) {
    return curriculum.buildCurriculum(p.userId);
  }

  @Put("curriculum/pathway")
  pathway(@CurrentPrincipal() p: Principal, @ZBody(PathwayIn) body: z.infer<typeof PathwayIn>) {
    return curriculum.setPathway(p.userId, body.pathway);
  }

  @Get("curriculum/quiz/:lessonId")
  quiz(@Param("lessonId") lessonId: string) {
    return curriculum.getQuiz(lessonId);
  }

  @PostOk("curriculum/quiz/:lessonId")
  submitQuiz(@Param("lessonId") lessonId: string, @CurrentPrincipal() p: Principal, @ZBody(AnswersIn) body: z.infer<typeof AnswersIn>) {
    return curriculum.submitQuiz(p.userId, lessonId, body.answers);
  }

  @Get("dashboard")
  dashboard(@CurrentPrincipal() p: Principal) {
    return curriculum.dashboard(p);
  }
}
