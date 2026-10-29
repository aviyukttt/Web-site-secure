import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, router } from "./_core/trpc";
import { TRPCError } from "@trpc/server";
import { z } from "zod";
import { consumeRateLimit, runPassiveScan } from "./scanner";

export const appRouter = router({
    // if you need to use socket.io, read and register route in server/_core/index.ts, all api should start with '/api/' so that the gateway can route correctly
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return {
        success: true,
      } as const;
    }),
  }),

  scan: router({
    run: publicProcedure
      .input(z.object({ target: z.string().trim().min(1).max(2048), authorized: z.literal(true) }))
      .mutation(async ({ input, ctx }) => {
        const clientKey = ctx.req.ip || ctx.req.headers["x-forwarded-for"]?.toString().split(",")[0] || "unknown";
        if (!consumeRateLimit(clientKey)) {
          throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "Scan limit reached. Please wait a minute before trying again." });
        }
        try {
          return await runPassiveScan(input.target);
        } catch (error) {
          const message = error instanceof Error ? error.message : "The target could not be assessed safely.";
          throw new TRPCError({ code: "BAD_REQUEST", message });
        }
      }),
  }),

  // TODO: add feature routers here, e.g.
  // todo: router({
  //   list: protectedProcedure.query(({ ctx }) =>
  //     db.getUserTodos(ctx.user.id)
  //   ),
  // }),
});

export type AppRouter = typeof appRouter;
