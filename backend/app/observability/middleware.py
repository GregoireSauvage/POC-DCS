from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.observability.perf import PerfContext, reset_perf_context, set_perf_context


class PerfMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ctx = PerfContext()
        token = set_perf_context(ctx)
        request.state.perf = ctx
        try:
            response: Response = await call_next(request)
        finally:
            reset_perf_context(token)
        response.headers["x-perf-total-ms"] = f"{ctx.elapsed_ms():.2f}"
        return response
