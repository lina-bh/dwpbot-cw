import nacl from "tweetnacl"

const UTF8ENC = new TextEncoder()

function hex2bin(hex) {
  const buf = new Uint8Array(hex.length / 2)
  let i
  for (i = 0; i < hex.length; i += 2) {
    const byte = parseInt(hex.slice(i, i + 2), 16)
    if (Number.isNaN(byte)) {
      break
    }
    buf[i / 2] = byte
  }
  return buf.subarray(0, i / 2)
}

function unauthorised401(): Response {
  return new Response(null, { status: 401 })
}

function error500(): Response {
  return new Response(null, { status: 500 })
}

function jsonify(obj, opts: ResponseInit = {}): Response {
  opts.headers = {
    ...opts.headers,
    "Content-Type": "application/json;charset=UTF-8",
  }
  return new Response(JSON.stringify(obj), opts)
}

async function verify(req: Request): Promise<boolean> {
  const body = await req.text()
  const sig = req.headers.get("X-Signature-Ed25519")
  if (!sig) {
    return false
  }
  const ts = req.headers.get("X-Signature-Timestamp")
  if (!ts) {
    return false
  }
  try {
    // return edVerify(sig, ts + body, DISCORD_PUBLIC_KEY)
    // return sodium.crypto_sign_verify_detached(
    //   sodium.from_hex(sig),
    //   ts + body,
    //   DISCORD_PUBLIC_KEY_BUF
    // )
    return nacl.sign.detached.verify(
      UTF8ENC.encode(ts + body),
      hex2bin(sig),
      DISCORD_PUBLIC_KEY_BUF
    )
  } catch (ex) {
    console.error(ex)
  }
  return false
}

async function respond(req: Request): Promise<Response> {
  if (!verify(req.clone())) {
    return unauthorised401()
  }
  const payload: any = await req.json()
  switch (payload.type) {
    case 1:
      console.log("PONG")
      return jsonify({ type: 1 })
  }
  return error500()
}

async function handleFetch(req: Request) {
  const ua = req.headers.get("User-Agent")
  console.log(ua)
  console.log(await req.clone().text())
  if (req.url != "/") {
    return new Response(null, { status: 404 })
  }
  if (ua.startsWith("Discord")) {
    const res = await respond(req)
    console.log(res.status, await res.clone().text())
    return res
  }
  return error500()
}

let DISCORD_PUBLIC_KEY, DISCORD_PUBLIC_KEY_BUF

// addEventListener("fetch", (ev) => ev.respondWith(handleFetch(ev)))
export default {
  fetch(request, env) {
    if (!DISCORD_PUBLIC_KEY) {
      DISCORD_PUBLIC_KEY = env.DISCORD_PUBLIC_KEY
      DISCORD_PUBLIC_KEY_BUF = hex2bin(DISCORD_PUBLIC_KEY)
    }
    return handleFetch(request)
  },
}
