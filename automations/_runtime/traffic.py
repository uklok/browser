from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import signal
from pathlib import Path
from typing import Any

import aiohttp


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


class CDPTrafficRecorder:
    def __init__(self, ws: aiohttp.ClientWebSocketResponse, output: Path):
        self.ws = ws
        self.output = output
        self.next_id = 0
        self.pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self.target_to_session: dict[str, str] = {}
        self.session_to_target: dict[str, dict[str, Any]] = {}
        self.attaching: set[str] = set()
        self.tasks: set[asyncio.Task[Any]] = set()
        self.handle = output.open("w", encoding="utf-8", buffering=1)

    def _spawn(self, coro: Any) -> None:
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def send(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        self.next_id += 1
        message: dict[str, Any] = {"id": self.next_id, "method": method, "params": params or {}}
        if session_id:
            message["sessionId"] = session_id

        future = asyncio.get_running_loop().create_future()
        self.pending[self.next_id] = future
        await self.ws.send_json(message)
        response = await asyncio.wait_for(future, timeout=5)
        if "error" in response:
            raise RuntimeError(f"{method}: {response['error']}")
        return response.get("result", {})

    async def enable_network(self, session_id: str) -> None:
        try:
            await self.send("Network.enable", session_id=session_id)
        except Exception:
            return

    async def attach_target(self, target: dict[str, Any]) -> None:
        target_id = target.get("targetId")
        if not target_id or target.get("type") != "page":
            return
        if target_id in self.target_to_session or target_id in self.attaching:
            return

        self.attaching.add(target_id)
        try:
            result = await self.send("Target.attachToTarget", {"targetId": target_id, "flatten": True})
            session_id = result.get("sessionId")
            if not session_id:
                return
            self.target_to_session[target_id] = session_id
            self.session_to_target[session_id] = target
            await self.enable_network(session_id)
        finally:
            self.attaching.discard(target_id)

    def emit(self, raw: dict[str, Any]) -> None:
        session_id = raw.get("sessionId")
        envelope = {
            "captured_at": _now(),
            "target": self.session_to_target.get(session_id),
            "cdp": raw,
        }
        self.handle.write(json.dumps(envelope, separators=(",", ":"), ensure_ascii=False) + "\n")

    async def reader(self) -> None:
        async for message in self.ws:
            if message.type != aiohttp.WSMsgType.TEXT:
                if message.type in {aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR}:
                    break
                continue

            raw = json.loads(message.data)
            response_id = raw.get("id")
            if response_id in self.pending:
                future = self.pending.pop(response_id)
                if not future.done():
                    future.set_result(raw)
                continue

            method = raw.get("method", "")
            params = raw.get("params") or {}

            if method == "Target.targetCreated":
                self._spawn(self.attach_target(params.get("targetInfo") or {}))
                continue

            if method == "Target.attachedToTarget":
                session_id = params.get("sessionId")
                target = params.get("targetInfo") or {}
                target_id = target.get("targetId")
                if session_id and target.get("type") == "page":
                    if target_id and target_id not in self.target_to_session:
                        self.target_to_session[target_id] = session_id
                    self.session_to_target[session_id] = target
                    self._spawn(self.enable_network(session_id))
                continue

            if method == "Target.detachedFromTarget":
                session_id = params.get("sessionId")
                target = self.session_to_target.pop(session_id, None)
                if target and target.get("targetId"):
                    self.target_to_session.pop(target["targetId"], None)
                continue

            if method.startswith("Network."):
                self.emit(raw)

        error = RuntimeError("CDP traffic observer disconnected")
        for future in self.pending.values():
            if not future.done():
                future.set_exception(error)
        self.pending.clear()

    async def setup(self) -> None:
        await self.send("Target.setDiscoverTargets", {"discover": True})
        targets = await self.send("Target.getTargets")
        for target in targets.get("targetInfos", []):
            if target.get("type") == "page":
                await self.attach_target(target)

        await self.send(
            "Target.setAutoAttach",
            {"autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True},
        )

    async def close(self) -> None:
        await self.ws.close()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        self.handle.close()


async def record(cdp_url: str, output: Path, ready_file: Path) -> None:
    version_url = cdp_url.rstrip("/") + "/json/version"
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(version_url) as response:
            response.raise_for_status()
            version = await response.json()

        ws_url = version.get("webSocketDebuggerUrl")
        if not ws_url:
            raise RuntimeError(f"CDP endpoint did not expose webSocketDebuggerUrl: {version_url}")

        async with session.ws_connect(ws_url, heartbeat=20) as ws:
            recorder = CDPTrafficRecorder(ws, output)
            reader = asyncio.create_task(recorder.reader())
            try:
                await recorder.setup()
                ready_file.write_text("ready\n", encoding="utf-8")

                stop_task = asyncio.create_task(stop.wait())
                done, _ = await asyncio.wait({reader, stop_task}, return_when=asyncio.FIRST_COMPLETED)
                if reader in done and not stop.is_set():
                    await reader
                    raise RuntimeError("CDP traffic observer stopped before the automation completed")
                stop_task.cancel()
            finally:
                ready_file.unlink(missing_ok=True)
                await recorder.close()
                if not reader.done():
                    reader.cancel()
                await asyncio.gather(reader, return_exceptions=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Observe raw Chrome Network.* CDP events without consuming Browser Harness events"
    )
    parser.add_argument("--cdp-url", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ready-file", required=True, type=Path)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    asyncio.run(record(args.cdp_url, args.output, args.ready_file))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
