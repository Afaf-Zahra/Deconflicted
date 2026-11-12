"""Call an ASGI app (a ledger node) from a synchronous httpx.Client without opening a socket."""
from __future__ import annotations

import asyncio

import httpx


class SyncASGITransport(httpx.BaseTransport):
    def __init__(self, app):
        self._transport = httpx.ASGITransport(app=app)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        async def run() -> httpx.Response:
            response = await self._transport.handle_async_request(request)
            await response.aread()
            return response
        raw = asyncio.run(run())
        # The sync client needs a response with a synchronous stream, so rebuild it from the bytes.
        return httpx.Response(raw.status_code, headers=raw.headers, content=raw.content, request=request)


def in_process_client(app) -> httpx.Client:
    return httpx.Client(transport=SyncASGITransport(app), base_url="http://node")
