#!/usr/bin/env python3
"""Minimal SOCKS5 proxy (stdlib asyncio only) for perf item 5.

No-auth greeting, CONNECT only, then byte relay. No logging of payload.
Usage: socks5.py --listen 127.0.0.1 --port 1080
"""
import argparse, asyncio

async def relay(src, dst):
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass

async def handle(reader, writer):
    try:
        hdr = await reader.readexactly(2)
        if hdr[0] != 5:
            return
        await reader.readexactly(hdr[1])
        writer.write(b"\x05\x00")
        await writer.drain()
        req = await reader.readexactly(4)
        if req[1] != 1:  # CONNECT only
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return
        atyp = req[3]
        if atyp == 1:
            addr = ".".join(str(b) for b in await reader.readexactly(4))
        elif atyp == 3:
            ln = (await reader.readexactly(1))[0]
            addr = (await reader.readexactly(ln)).decode()
        else:
            return
        port = int.from_bytes(await reader.readexactly(2), "big")
        try:
            target_r, target_w = await asyncio.open_connection(addr, port)
        except OSError:
            writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        await asyncio.gather(relay(reader, target_w), relay(target_r, writer))
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1080)
    a = ap.parse_args()
    srv = await asyncio.start_server(handle, a.listen, a.port)
    print(f"socks5 listening {a.listen}:{a.port}", flush=True)
    async with srv:
        await srv.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
