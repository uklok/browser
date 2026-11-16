import json


HONEYPOT_ORIGIN = "http://a.reading.test"
TEST_SECRET = "reading-honeypot-secret-1842"
FIELD_SECRET = "NonsensitiveOpaqueValue"
OPAQUE_TOKEN = "jStkcFiTKsVzcqdhcpWMPdYC"


def step_open_honeypot(ctx):
    target = HONEYPOT_ORIGIN + "/health"
    new_tab(target)
    wait_for_load()
    title = str(js("document.title") or "").strip()
    return {
        "ok": title == "reading honeypot",
        "observed": {"target": target, "title": title, "current_url": str(js("location.href"))},
    }


def step_exercise(ctx):
    trap = str(ctx["inputs"]["trap"] or "none")
    allowed_traps = {"none", "graphql_comment", "field_name"}
    if trap not in allowed_traps:
        return {
            "ok": False,
            "observed": {"error": f"unsupported trap: {trap}", "allowed": sorted(allowed_traps)},
        }
    observed = js(
        """
        (async () => {
          const secret = %s;
          const fieldSecret = %s;
          const opaque = %s;
          const trap = %s;
          const calls = [];
          async function record(name, run) {
            try {
              const response = await run();
              const body = await response.arrayBuffer();
              calls.push({
                name,
                ok: response.ok,
                status: response.status,
                url: response.url,
                type: response.type,
                body_bytes: body.byteLength,
              });
            } catch (error) {
              calls.push({name, ok: false, error: String(error)});
            }
          }
          await record("redirect", () => fetch("http://a.reading.test/redirect/start", {
            method: "POST",
            headers: {"Authorization": "Bearer " + secret, "Content-Type": "application/json"},
            body: JSON.stringify({amount: 5, note: "open"}),
            redirect: "follow",
          }));
          await record("acknowledgements", () => fetch("http://api.reading.test/acknowledgements"));
          await record("profile", () => fetch("http://api.reading.test/GetCurrentUserProfile"));
          await record("opaque", () => fetch("http://api.reading.test/challenge/" + opaque));
          await record("vocabulary", () => fetch("http://api.reading.test/items", {
            method: "POST",
            headers: {"Authorization": "Bearer Authorization", "Content-Type": "application/json"},
            body: JSON.stringify({name: "ordinary"}),
          }));
          await record("graphql-json", () => fetch("http://api.reading.test/graphql", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({operationName: "GetThing", query: "query GetThing { thing { id } }"}),
          }));
          await record("graphql-get", () => fetch("http://api.reading.test/graphql?query=" + encodeURIComponent("query GetThing { thing { id } }")));
          await record("graphql-batch", () => fetch("http://api.reading.test/graphql", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify([{query: "query A { a }"}, {query: "query B { b }"}]),
          }));
          await record("graphql-persisted", () => fetch("http://api.reading.test/graphql", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({operationName: "PersistedThing", extensions: {persistedQuery: {sha256Hash: "%s"}}}),
          }));
          await record("graphql-hash", () => fetch("http://api.reading.test/graphql", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({extensions: {persistedQuery: {sha256Hash: "%s"}}}),
          }));
          await record("graphql-raw", () => fetch("http://api.reading.test/graphql", {
            method: "POST",
            headers: {"Content-Type": "application/graphql"},
            body: "query GetThing { thing { id } }",
          }));
          await record("case-upper", () => fetch("http://API.reading.test/case"));
          await record("case-lower", () => fetch("http://api.reading.test/case"));
          await record("port-explicit", () => fetch("http://port.reading.test:80/default"));
          await record("port-default", () => fetch("http://port.reading.test/default"));
          for (let n = 1000; n < 1020; n += 1) {
            await record("bucket-" + n, () => fetch("http://api.reading.test/bucket/" + n));
          }
          if (trap === "graphql_comment") {
            await record("graphql-comment", () => fetch("http://api.reading.test/graphql", {
              method: "POST",
              headers: {"Authorization": "Bearer " + secret, "Content-Type": "application/json"},
              body: JSON.stringify({operationName: "Echo", query: "query Echo { thing { id } } # note " + secret}),
            }));
          }
          if (trap === "field_name") {
            await record("field-name", () => fetch("http://api.reading.test/items", {
              method: "POST",
              headers: {"Authorization": "Bearer " + fieldSecret, "Content-Type": "application/json"},
              body: JSON.stringify({[fieldSecret]: "ordinary-value"}),
            }));
          }
          return calls;
        })()
        """
        % (
            json.dumps(TEST_SECRET),
            json.dumps(FIELD_SECRET),
            json.dumps(OPAQUE_TOKEN),
            json.dumps(trap),
            "a" * 64,
            "b" * 64,
        )
    )
    expected_count = 35 if trap == "none" else 36
    ok = (
        isinstance(observed, list)
        and len(observed) == expected_count
        and all(isinstance(item, dict) and bool(item.get("ok")) for item in observed)
    )
    return {
        "ok": ok,
        "observed": observed,
    }
