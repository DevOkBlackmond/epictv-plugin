/*! EpicTVPlugin 1.0.1 — ZUPER API 4 */

// src/util.mjs
var API_ORIGIN = "https://playlatam.site";
var API_ORIGINS = [API_ORIGIN, "https://api.entrada-sur.workers.dev"];
var text = (value) => typeof value === "string" ? value : typeof value === "number" && Number.isFinite(value) ? String(value) : "";
var object = (value) => value && typeof value === "object" && !Array.isArray(value) ? value : {};
var array = (value) => Array.isArray(value) ? value : [];
function fault(kino, code, message) {
  return kino.error(code, message, { userMessage: message });
}
function safeUrl(value, base = API_ORIGIN) {
  let url = text(value).trim();
  if (!url || url.length > 8192 || /[\s\x00-\x1f\x7f\\]/.test(url)) return "";
  const b = /^(https?):\/\/([^/?#]+)([^?#]*)/i.exec(text(base));
  if (url.startsWith("//")) url = (b?.[1] || "https") + ":" + url;
  else if (!/^[a-z][a-z0-9+.-]*:/i.test(url)) {
    if (!b) return "";
    const origin = b[1] + "://" + b[2];
    if (url[0] === "/") url = origin + url;
    else if (url[0] === "?") url = origin + (b[3] || "/") + url;
    else url = origin + (b[3] || "/").replace(/[^/]*$/, "") + url;
  }
  const m = /^(https?):\/\/([^/?#]+)(.*)$/i.exec(url);
  if (!m || !/^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?|\[[a-f0-9:]+\])(?::[0-9]{1,5})?$/i.test(m[2])) return "";
  const port = /:([0-9]+)$/.exec(m[2]);
  if (port && (Number(port[1]) < 1 || Number(port[1]) > 65535)) return "";
  return m[1].toLowerCase() + "://" + m[2].toLowerCase() + (m[3] || "/");
}
function originOf(value) {
  const m = /^(https?):\/\/([^/?#]+)/.exec(safeUrl(value));
  if (!m) return "";
  return m[1] + "://" + m[2].replace(m[1] === "https" ? /:443$/ : /:80$/, "");
}
function encodeRef(kind, data = {}) {
  return "epic1:" + encodeURIComponent(JSON.stringify({ ...object(data), kind }));
}
function decodeRef(value) {
  const ref = text(value);
  if (!ref.startsWith("epic1:") || ref.length > 4096) return {};
  try {
    return object(JSON.parse(decodeURIComponent(ref.slice(6))));
  } catch {
    return {};
  }
}
function queryString(values) {
  return Object.entries(object(values)).filter(([, v]) => v !== void 0 && v !== null && v !== "").map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(text(v))).join("&");
}
function cleanHeaders(value) {
  const headers = /* @__PURE__ */ Object.create(null);
  for (const [key, raw] of Object.entries(object(value))) {
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(key) || typeof raw !== "string" || /[\r\n\x00]/.test(raw)) continue;
    if (["host", "content-length", "connection", "transfer-encoding"].includes(key.toLowerCase())) continue;
    headers[key] = raw;
  }
  return headers;
}

// src/client.mjs
var ALLOWED_PATHS = /* @__PURE__ */ new Set(["/registrar", "/menu", "/canales", "/receta", "/resolve", "/vod/inicio", "/vod/buscar", "/vod/titulo", "/vod/play", "/vod/capfotos", "/vod/perelman"]);
var BACKOFF = [6e4, 3e5, 18e5, 216e5];
var MAX_AGE_MS = 150 * 864e5;
var EPIC_HEADERS = /* @__PURE__ */ new Set(["x-cred", "x-llave", "x-aparato", "x-app-version", "x-ap", "x-cif"]);
var sensitiveHeader = (name) => {
  const value = name.toLowerCase();
  return ["authorization", "proxy-authorization", "cookie", "cookie2", "content-auth", "content-license", "api-key", "x-api-key", "x-request-source"].includes(value) || /authorization|auth-token|access-token|secret|signature|session|license|credential/.test(value) || /-(key|token)$/.test(value);
};
function createClient(kino, { now = () => Date.now() } = {}) {
  let registration = null;
  const memory = /* @__PURE__ */ new Map();
  const read = (key) => {
    try {
      return object(JSON.parse(kino.storage.get("epic." + key) || "{}"));
    } catch {
      return {};
    }
  };
  const write = (key, value) => kino.storage.set("epic." + key, JSON.stringify(value));
  const remove = (key) => kino.storage.remove("epic." + key);
  function integration() {
    const configured = text(kino.config.get("apiKey")).trim();
    if (configured) {
      if (!/^[\x21-\x7e]{32}$/.test(configured)) throw fault(kino, "auth_required", "La clave de acceso de EpicTV debe tener 32 caracteres.");
      return configured;
    }
    throw fault(kino, "auth_required", "Configura la clave de acceso de EpicTV en los ajustes del plugin.");
  }
  function identity() {
    const saved = read("installation");
    if (/^[a-f0-9]{8}$/.test(saved.id || "")) return saved.id;
    const id = kino.crypto.randomBytes(4, "hex");
    if (!/^[a-f0-9]{8}$/.test(id)) throw fault(kino, "unavailable", "No se pudo guardar la instalación de EpicTV.");
    write("installation", { id });
    return id;
  }
  function scope() {
    return kino.crypto.hash("sha256", integration());
  }
  function generation() {
    return text(read("generation").value);
  }
  function origin() {
    const saved = read("origin").value;
    return API_ORIGINS.includes(saved) ? saved : API_ORIGIN;
  }
  function valid(saved, keyScope = scope()) {
    if (saved.scope !== keyScope || typeof saved.credential !== "string" || saved.credential.split(".").length !== 4) return false;
    const from = Number(saved.credential.split(".")[2]);
    return Number.isFinite(from) && from > 0 && now() < from * 1e3 + MAX_AGE_MS;
  }
  function current() {
    const saved = read("session");
    return valid(saved) ? saved : null;
  }
  async function wire(path2, params, headers, timeoutMs = 12e3) {
    if (!ALLOWED_PATHS.has(path2)) throw fault(kino, "invalid_request", "Operación de EpicTV no admitida.");
    const query = queryString(params);
    const first = origin();
    const bases = [first, ...API_ORIGINS.filter((base) => base !== first)];
    for (let index = 0; index < bases.length; index++) {
      let response;
      try {
        response = await kino.fetch(bases[index] + path2 + (query ? "?" + query : ""), {
          headers,
          redirect: "manual",
          cookies: false,
          timeoutMs: Math.min(3e4, timeoutMs)
        });
      } catch {
        if (index + 1 < bases.length) continue;
        throw fault(kino, "unavailable", "No se pudo conectar con EpicTV.");
      }
      if (response.status >= 500 && response.status <= 599 && index + 1 < bases.length) continue;
      if (response.status >= 300 && response.status < 400) throw fault(kino, "unavailable", "EpicTV redirigió la conexión a un destino no verificado.");
      if (response.ok) write("origin", { value: bases[index] });
      return response;
    }
    throw fault(kino, "unavailable", "EpicTV no respondió.");
  }
  async function body(response) {
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) throw fault(kino, "auth_required", "EpicTV no autorizó esta consulta.");
      if (response.status === 429) throw fault(kino, "unavailable", "EpicTV ha limitado las consultas. Inténtalo más tarde.");
      throw fault(kino, "unavailable", "EpicTV no pudo completar la consulta.");
    }
    const raw = await response.text();
    if (raw.startsWith("CIF1")) throw fault(kino, "unavailable", "EpicTV envió una respuesta cifrada que esta integración no admite.");
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw fault(kino, "unavailable", "EpicTV devolvió una respuesta no válida.");
    }
    if (!parsed || typeof parsed !== "object") throw fault(kino, "unavailable", "EpicTV devolvió una respuesta vacía.");
    if (!Array.isArray(parsed) && (parsed.ok === false || parsed.activo === false)) {
      throw fault(kino, "unavailable", "EpicTV no tiene disponible esta consulta para la instalación actual.");
    }
    return parsed;
  }
  async function ensure() {
    const keyScope = scope();
    const saved = read("session");
    if (valid(saved, keyScope)) return saved;
    if (registration) return registration;
    const startGeneration = generation();
    const failed = read("failure");
    if (failed.scope === keyScope && failed.next > now()) throw fault(kino, "unavailable", "La conexión de EpicTV está en espera tras un intento fallido.");
    registration = (async () => {
      try {
        const data = await body(await wire("/registrar", {}, { "X-Llave": integration(), "X-Aparato": identity(), "X-App-Version": "186" }));
        const credential = text(data.credencial).trim();
        if (credential.split(".").length !== 4 || credential.split(".").some((part) => !part) || /[\r\n\x00]/.test(credential)) {
          throw fault(kino, "unavailable", "EpicTV no devolvió una credencial de instalación válida.");
        }
        if (generation() !== startGeneration || scope() !== keyScope) throw fault(kino, "unavailable", "La configuración de EpicTV cambió durante la conexión.");
        const session = { credential, scope: keyScope, obtained: now() };
        if (!valid(session, keyScope)) throw fault(kino, "auth_required", "EpicTV devolvió una credencial vencida.");
        write("session", session);
        remove("failure");
        return session;
      } catch (error) {
        if (generation() === startGeneration && scope() === keyScope) {
          const count = failed.scope === keyScope ? Math.min(3, (failed.count || 0) + 1) : 0;
          write("failure", { scope: keyScope, count, next: now() + BACKOFF[count] });
        }
        throw error;
      } finally {
        registration = null;
      }
    })();
    return registration;
  }
  async function get(path2, params = {}, options = {}) {
    if (path2 === "/registrar") throw fault(kino, "invalid_request", "El registro es automático.");
    const startGeneration = generation();
    const startScope = scope();
    const first = await ensure();
    const request = (session) => wire(path2, params, { "X-Cred": session.credential, "X-Aparato": identity() }, options.timeoutMs);
    let response = await request(first);
    if (response.status === 401) {
      if (generation() !== startGeneration) throw fault(kino, "auth_required", "La sesión de EpicTV cambió.");
      const latest = current();
      if (!latest || latest.credential === first.credential) remove("session");
      const renewed = latest && latest.credential !== first.credential ? latest : await ensure();
      response = await request(renewed);
      if (response.status === 401) {
        const latestAgain = read("session");
        if (latestAgain.credential === renewed.credential) {
          remove("session");
          write("failure", { scope: renewed.scope, count: 0, next: now() + BACKOFF[0] });
        }
      }
    }
    if (generation() !== startGeneration || scope() !== startScope) throw fault(kino, "auth_required", "La sesión de EpicTV cambió.");
    return body(response);
  }
  async function cached(key, ttlMs, loader) {
    const cacheKey = scope() + ":" + generation() + ":" + key;
    const saved = memory.get(cacheKey);
    if (saved && saved.until > now()) return saved.value;
    if (memory.size >= 48) memory.delete(memory.keys().next().value);
    const value = Promise.resolve().then(loader);
    memory.set(cacheKey, { value, until: now() + Math.max(0, Math.min(ttlMs, 3e5)) });
    try {
      return await value;
    } catch (error) {
      if (memory.get(cacheKey)?.value === value) memory.delete(cacheKey);
      throw error;
    }
  }
  async function mediaHeaders(url, raw = {}) {
    const headers = cleanHeaders(raw);
    for (const name of Object.keys(headers)) if (EPIC_HEADERS.has(name.toLowerCase())) delete headers[name];
    return headers;
  }
  async function signContext() {
    const session = await ensure();
    const iv = kino.crypto.randomBytes(12, "hex");
    const data = kino.crypto.encrypt("aes-256-gcm", {
      key: scope(),
      keyEncoding: "hex",
      iv,
      ivEncoding: "hex",
      data: JSON.stringify({ credential: session.credential, device: identity() }),
      aad: "epictv-pluginapp:sign:1",
      inputEncoding: "utf8",
      outputEncoding: "base64"
    });
    return `epic-sign:1:${iv}:${data}`;
  }
  function signedHeaders(url, context) {
    if (!/^https:\/\//i.test(text(url)) || !API_ORIGINS.includes(originOf(url))) return {};
    try {
      const match = /^epic-sign:1:([a-f0-9]{24}):([A-Za-z0-9+/=]{24,6000})$/.exec(text(context));
      if (!match) throw new Error("Invalid context");
      const keyScope = scope();
      const session = object(JSON.parse(kino.crypto.decrypt("aes-256-gcm", {
        key: keyScope,
        keyEncoding: "hex",
        iv: match[1],
        ivEncoding: "hex",
        data: match[2],
        aad: "epictv-pluginapp:sign:1",
        inputEncoding: "base64",
        outputEncoding: "utf8"
      })));
      if (!valid({ ...session, scope: keyScope }, keyScope) || !/^[a-f0-9]{8}$/.test(session.device) || /[\r\n\x00]/.test(session.credential)) throw new Error("Invalid session");
      return { "X-Cred": session.credential, "X-Aparato": session.device };
    } catch {
      throw fault(kino, "auth_required", "La conexión de EpicTV venció o cambió. Vuelve a abrir el vídeo.");
    }
  }
  async function fetchExternal(value, options = {}) {
    let url = safeUrl(value);
    if (!url || API_ORIGINS.includes(originOf(url))) throw fault(kino, "invalid_request", "Destino de extracción no admitido.");
    let headers = cleanHeaders(options.headers);
    for (const name of Object.keys(headers)) if (EPIC_HEADERS.has(name.toLowerCase())) delete headers[name];
    let method = options.method || "GET";
    let requestBody = options.body;
    for (let i = 0; i < 4; i++) {
      const response = await kino.fetch(url, { ...options, method, body: requestBody, headers, cookies: false, redirect: "manual", timeoutMs: Math.min(15e3, options.timeoutMs || 12e3) });
      if (![301, 302, 303, 307, 308].includes(response.status)) return response;
      const location = Object.entries(object(response.headers)).find(([name]) => name.toLowerCase() === "location")?.[1];
      const target = safeUrl(location, url);
      if (!target || API_ORIGINS.includes(originOf(target)) || url.startsWith("https:") && target.startsWith("http:")) break;
      if (originOf(target) !== originOf(url)) {
        for (const name of Object.keys(headers)) if (sensitiveHeader(name)) delete headers[name];
        if (method !== "GET" && method !== "HEAD") break;
      }
      if (response.status === 303 || [301, 302].includes(response.status) && method === "POST") {
        method = "GET";
        requestBody = void 0;
      }
      url = target;
    }
    throw fault(kino, "unavailable", "La fuente redirigió la conexión de forma no admitida.");
  }
  async function reconnect() {
    write("generation", { value: kino.crypto.randomBytes(8, "hex") });
    remove("session");
    remove("failure");
    memory.clear();
    if (registration) {
      try {
        await registration;
      } catch {
      }
    }
    await ensure();
  }
  function status() {
    try {
      return current() ? "Instalación conectada" : (integration(), "Preparado para conectar");
    } catch {
      return "Falta configurar la clave de acceso";
    }
  }
  return { get, cached, origin, mediaHeaders, signContext, signedHeaders, fetchExternal, reconnect, status, ensure };
}

// src/catalog.mjs
var TITLE_ID = /^[0-9a-f]{32}$/i;
var PUBLIC_ID = /^[A-Za-z0-9._~-]{1,128}$/;
var HOME_ROWS = 20;
var ROW_ITEMS = 60;
var PAGE_ITEMS = 100;
var LIVE_PAGE_ITEMS = 250;
var MAX_SEASONS = 50;
var MAX_EPISODES = 5e3;
var CATALOG_TTL = 5 * 6e4;
var DETAIL_TTL = 2 * 6e4;
var record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
var string = (value) => typeof value === "string" ? value.trim() : typeof value === "number" && Number.isFinite(value) ? String(value) : "";
var list = (value) => Array.isArray(value) ? value : [];
var integer = (value) => Number.isInteger(Number(value)) && Number(value) >= 0 && string(value) !== "" ? Number(value) : null;
var uniqueStrings = (values) => [...new Set(list(values).map(string).filter(Boolean))];
function createCatalog({ kino, client }) {
  const fail = (code, message) => {
    throw fault(kino, code, message);
  };
  const hash = (value) => kino.crypto.hash("sha256", value);
  const country = () => {
    const value = string(kino.config?.get("country")).toUpperCase();
    return /^[A-Z]{2}$/.test(value) ? value : "";
  };
  const image = (value) => {
    const result = safeUrl(value, client.origin());
    return typeof result === "string" && result.length <= 2048 && /^https:\/\//i.test(result) ? result : "";
  };
  const poster = (id) => image(`/vod/cartel/${id}.jpg`);
  function refOf(value, kinds) {
    let decoded;
    try {
      decoded = decodeRef(value);
    } catch {
    }
    if (!record(decoded) || !kinds.includes(decoded.kind)) fail("not_found", "No se encontró ese contenido de EpicTV.");
    const id = string(decoded.id);
    if (["movie", "series", "episode"].includes(decoded.kind) && !TITLE_ID.test(id)) fail("not_found", "El identificador del contenido no es válido.");
    if (decoded.kind === "live" && !PUBLIC_ID.test(id)) fail("not_found", "El identificador del canal no es válido.");
    if (decoded.kind === "section" && (!id || id.length > 200)) fail("not_found", "La sección no es válida.");
    return { ...decoded, id };
  }
  function requireVod(body, active = false) {
    if (!record(body) || body.ok !== true) fail("unavailable", "EpicTV no pudo entregar este contenido.");
    if (active && body.activo !== true || body.activo === false || body.disponible === false) {
      fail("unavailable", "Este contenido de EpicTV no está disponible para esta instalación.");
    }
    return body;
  }
  function offsetOf(cursor) {
    if (cursor == null || cursor === "") return 0;
    if (typeof cursor !== "string" || !/^(0|[1-9]\d*)$/.test(cursor)) fail("not_found", "La página solicitada no es válida.");
    const offset = Number(cursor);
    if (!Number.isSafeInteger(offset)) fail("not_found", "La página solicitada no es válida.");
    return offset;
  }
  function page(items, offset, size) {
    const result = { items: items.slice(offset, offset + size) };
    if (offset + size < items.length) result.next = String(offset + size);
    return result;
  }
  function titleItem(raw, wantedSeason = null) {
    if (!record(raw) || !TITLE_ID.test(string(raw.id)) || !string(raw.nombre)) return null;
    const id = string(raw.id);
    const kind = raw.tipo === "serie" ? "series" : "movie";
    const sourceSeason = integer(raw.temporada);
    const refData = { id };
    if (kind === "series") {
      const season = wantedSeason ?? sourceSeason;
      if (season !== null) refData.season = season;
    }
    const item = { id, title: string(raw.nombre), kind, ref: encodeRef(kind, refData) };
    const year = integer(raw.anio);
    if (year && year >= 1870 && year <= 2100) item.year = String(year);
    const genres = uniqueStrings(raw.generos).slice(0, 5);
    if (genres.length) item.genres = genres;
    if (string(raw.cartel)) item.poster = poster(id);
    const large = string(raw.cartel_grande);
    if (large) {
      const query = large.includes("?") ? "?" + large.split("?").slice(1).join("?").split("#")[0] : "";
      item.backdrop = image(`/vod/cartelg/${id}.jpg${query}`);
    }
    return item;
  }
  function titleItems(raw, wantedSeason = null) {
    const seen = /* @__PURE__ */ new Set();
    return list(raw).map((value) => titleItem(value, wantedSeason)).filter((value) => {
      if (!value || seen.has(value.id)) return false;
      seen.add(value.id);
      return true;
    });
  }
  const start = (section) => client.cached(`vod:home:${section}`, CATALOG_TTL, async () => {
    const body = requireVod(await client.get("/vod/inicio", section ? { seccion: section } : {}), true);
    if (!Array.isArray(body.filas)) fail("unavailable", "El catálogo de EpicTV tiene un formato inesperado.");
    return body;
  });
  async function home2() {
    const body = await start("");
    return body.filas.filter(record).map((row, index) => {
      const section = string(row.seccion);
      const items = titleItems(row.items).slice(0, ROW_ITEMS);
      const result = { id: `row-${index}`, title: string(row.titulo) || string(row.seccion) || "EpicTV", items };
      if (section) result.ref = encodeRef("section", { id: section });
      return result;
    }).filter((row) => row.items.length).slice(0, HOME_ROWS);
  }
  async function browse2(ref, cursor) {
    const selected = refOf(ref, ["section"]);
    const offset = offsetOf(cursor);
    const body = await start(selected.id);
    return page(titleItems(body.filas.filter(record).flatMap((row) => list(row.items))), offset, PAGE_ITEMS);
  }
  async function search2(query = {}) {
    if (typeof query === "string") query = { q: query };
    if (!record(query)) return { items: [] };
    const q = string(query.q);
    if (!q) return { items: [] };
    const cursor = string(query.cursor);
    if (q.length > 500 || cursor.length > 2048) fail("not_found", "La búsqueda solicitada no es válida.");
    const requestedSeason = integer(query.season);
    const explicitSpecials = requestedSeason === 0 && query.type === "series" && integer(query.episode) > 0;
    const wantedSeason = requestedSeason > 0 || explicitSpecials ? requestedSeason : null;
    if (wantedSeason > 999) fail("not_found", "La temporada solicitada supera el límite de la aplicación.");
    const searchId = hash(JSON.stringify([q, query.type === "movie" || query.type === "series" ? query.type : "any", wantedSeason]));
    let remoteCursor = "";
    let offset = 0;
    if (cursor) {
      const state = decodeRef(cursor);
      if (!record(state) || state.kind !== "search-page" || state.search !== searchId || typeof state.cursor !== "string") {
        fail("not_found", "La página solicitada no corresponde a esta búsqueda.");
      }
      remoteCursor = state.cursor;
      offset = offsetOf(state.offset);
    }
    const params = { q, ...remoteCursor ? { desde: remoteCursor } : {} };
    const body = await client.cached(`vod:search:${JSON.stringify(params)}`, DETAIL_TTL, async () => {
      const result2 = requireVod(await client.get("/vod/buscar", params), true);
      if (!Array.isArray(result2.items)) fail("unavailable", "La búsqueda de EpicTV tiene un formato inesperado.");
      return result2;
    });
    let items = titleItems(body.items, wantedSeason);
    if (query.type === "movie" || query.type === "series") items = items.filter((item) => item.kind === query.type);
    const result = { items: items.slice(offset, offset + PAGE_ITEMS) };
    const next = string(body.siguiente);
    const moreLocal = offset + PAGE_ITEMS < items.length;
    if (moreLocal || next && next !== remoteCursor) {
      const nextRef = encodeRef("search-page", {
        search: searchId,
        cursor: moreLocal ? remoteCursor : next,
        offset: moreLocal ? String(offset + PAGE_ITEMS) : "0"
      });
      if (nextRef.length > 2048) fail("unavailable", "EpicTV devolvió una página de búsqueda no compatible.");
      result.next = nextRef;
    }
    return result;
  }
  const title = (id) => client.cached(`vod:title:${id}`, DETAIL_TTL, async () => {
    const body = requireVod(await client.get("/vod/titulo", { id, de: "-" }));
    if (!string(body.nombre) || !string(body.tipo)) fail("unavailable", "La ficha de EpicTV tiene un formato inesperado.");
    return { ...body, id: TITLE_ID.test(string(body.id)) ? string(body.id) : id };
  });
  function metadata(body) {
    const result = { title: string(body.nombre) };
    const overview = string(body.sinopsis);
    if (overview) result.overview = overview;
    const genres = uniqueStrings(body.generos).slice(0, 5);
    if (genres.length) result.genres = genres;
    const year = integer(body.anio);
    if (year && year >= 1870 && year <= 2100) result.year = String(year);
    const runtime = integer(body.duracion_min);
    if (runtime && runtime <= 1e3) result.runtimeMinutes = runtime;
    const art = poster(body.id);
    if (art) result.poster = art;
    const backdrop = image(string(body.fondo)) || image(`/vod/ancha/${body.id}.jpg`);
    if (backdrop) result.backdrop = backdrop;
    return result;
  }
  async function details2(ref) {
    const selected = refOf(ref, ["movie", "series"]);
    return metadata(await title(selected.id));
  }
  function seasonList(body) {
    const seen = /* @__PURE__ */ new Set();
    const seasons = list(body.temporadas).filter(record).map((raw) => ({ id: string(raw.id), number: integer(raw.n) })).filter((season) => {
      if (!TITLE_ID.test(season.id) || season.number === null || season.number > 999 || seen.has(season.id)) return false;
      seen.add(season.id);
      return true;
    });
    const currentNumber = integer(body.temporada);
    if (currentNumber !== null && currentNumber <= 999 && !seen.has(body.id)) seasons.push({ id: body.id, number: currentNumber });
    return seasons.sort((a, b) => a.number - b.number || a.id.localeCompare(b.id));
  }
  async function episodes2(ref) {
    const selected = refOf(ref, ["series"]);
    let body = await title(selected.id);
    if (body.tipo !== "serie") fail("not_found", "Este contenido no es una serie.");
    let seasons = seasonList(body);
    const wanted = integer(selected.season);
    if (wanted > 999) fail("not_found", "La temporada solicitada supera el límite de la aplicación.");
    if (wanted !== null) {
      const target = seasons.find((season2) => season2.number === wanted && season2.id === body.id) || seasons.find((season2) => season2.number === wanted);
      if (!target) fail("not_found", "No se encontró la temporada solicitada.");
      if (target.id !== body.id) {
        body = await title(target.id);
        if (body.tipo !== "serie") fail("not_found", "La temporada solicitada no está disponible.");
        const moreSeasons = seasonList(body);
        const known = new Map(seasons.map((season2) => [season2.id, season2]));
        for (const season2 of moreSeasons) known.set(season2.id, season2);
        seasons = [...known.values()].sort((a, b) => a.number - b.number || a.id.localeCompare(b.id));
      }
    }
    const knownCurrent = seasons.find((season2) => season2.id === body.id);
    const season = integer(body.temporada) ?? knownCurrent?.number ?? null;
    if (season > 999) fail("unavailable", "La temporada de EpicTV supera el límite de la aplicación.");
    if (wanted !== null && season !== wanted) fail("not_found", "EpicTV no devolvió la temporada solicitada.");
    if (!Array.isArray(body.capitulos)) fail("unavailable", "La lista de episodios de EpicTV tiene un formato inesperado.");
    if (body.capitulos.length > MAX_EPISODES) fail("unavailable", "Esta temporada supera el límite de episodios de la aplicación.");
    const seen = /* @__PURE__ */ new Set();
    const items = body.capitulos.map((raw, index) => {
      if (!record(raw)) return null;
      const id = string(raw.id);
      if (!TITLE_ID.test(id) || seen.has(id)) return null;
      seen.add(id);
      const number = raw.n == null ? index + 1 : integer(raw.n);
      if (number === null || number < 1 || number > 99999) return null;
      const data = { id, serie: body.id, episode: number, ...season !== null ? { season } : {} };
      const item = { ref: encodeRef("episode", data), number, title: string(raw.nombre) || `Episodio ${number}` };
      if (season !== null) item.season = season;
      const runtime = integer(raw.duracion_min);
      if (runtime && runtime <= 1e3) item.runtimeMinutes = runtime;
      return item;
    }).filter(Boolean);
    if (body.capitulos.length && !items.length) fail("unavailable", "EpicTV no devolvió episodios válidos.");
    const selectedIndex = Math.max(0, seasons.findIndex((value) => value.id === body.id));
    const from = Math.max(0, Math.min(selectedIndex - Math.floor(MAX_SEASONS / 2), seasons.length - MAX_SEASONS));
    return {
      episodes: items,
      series: metadata(body),
      seasons: seasons.slice(from, from + MAX_SEASONS).map((value) => ({
        id: `season-${value.id}`,
        number: value.number,
        title: value.number === 0 ? "Especiales" : `Temporada ${value.number}`,
        ref: encodeRef("series", { id: value.id, season: value.number }),
        current: value.id === body.id
      }))
    };
  }
  function liveIdentity(raw) {
    const id = string(raw.id);
    if (PUBLIC_ID.test(id) && !id.startsWith("~")) return id;
    const route = string(raw.url).split(/[?#]/)[0];
    return "c-" + hash(JSON.stringify([id, string(raw.name), string(raw.folder), string(raw.seccion), string(raw.pais), route])).slice(0, 40);
  }
  const categoryName = (raw) => string(raw.folder) || string(raw.seccion) || "Otros";
  const categoryId = (raw) => "g-" + hash(categoryName(raw)).slice(0, 32);
  async function channels() {
    const region = country();
    return client.cached(`live:channels:${region}`, CATALOG_TTL, async () => {
      const params = { dev: "0", v: "186", recetas: "aparte", forma: "2", ...region ? { pais: "1", pais_app: region } : {} };
      const body = await client.get("/canales", params);
      if (record(body) && (body.ok === false || body.activo === false)) fail("unavailable", "EpicTV no habilitó el catálogo de canales para esta instalación.");
      const rows = Array.isArray(body) ? body : record(body) && Array.isArray(body.canales) ? body.canales : null;
      if (!rows) fail("unavailable", "El catálogo de canales de EpicTV tiene un formato inesperado.");
      const seen = /* @__PURE__ */ new Set();
      return rows.filter(record).filter((raw) => string(raw.name)).map((raw) => ({ id: liveIdentity(raw), raw })).filter((value) => {
        if (seen.has(value.id)) return false;
        seen.add(value.id);
        return true;
      });
    });
  }
  function liveItem({ id, raw }) {
    const item = { id, name: string(raw.name).slice(0, 200), title: string(raw.name).slice(0, 200), ref: encodeRef("live", { id }), categoryId: categoryId(raw) };
    const logo = image(string(raw.logo));
    if (logo) item.logo = logo;
    if (raw.adult === true) item.adult = true;
    return item;
  }
  async function liveCategories2() {
    const all = await channels();
    const groups = /* @__PURE__ */ new Map();
    for (const { raw } of all) groups.set(categoryId(raw), categoryName(raw));
    return [{ id: "all", title: "Todos" }, ...[...groups].slice(0, 199).map(([id, title2]) => ({ id, title: title2.slice(0, 200) }))];
  }
  async function liveChannels2(args = {}) {
    if (!record(args)) args = {};
    const selected = string(args.categoryId) || "all";
    const offset = offsetOf(args.cursor);
    const all = await channels();
    if (selected !== "all" && !all.some(({ raw }) => categoryId(raw) === selected)) fail("not_found", "No se encontró esa categoría de canales.");
    return page(all.filter(({ raw }) => selected === "all" || categoryId(raw) === selected).map(liveItem), offset, LIVE_PAGE_ITEMS);
  }
  async function liveSearch2(args = {}) {
    if (typeof args === "string") args = { query: args };
    if (!record(args)) return { items: [] };
    const query = string(args.query).toLocaleLowerCase();
    if (!query) return { items: [] };
    const offset = offsetOf(args.cursor);
    const all = await channels();
    const found = all.filter(({ raw }) => [raw.name, raw.id, raw.pais, raw.folder, raw.seccion].some((value) => string(value).toLocaleLowerCase().includes(query)));
    return page(found.map(liveItem), offset, PAGE_ITEMS);
  }
  async function channel(ref) {
    const selected = refOf(ref, ["live"]);
    const found = (await channels()).find((value) => value.id === selected.id);
    if (!found) fail("not_found", "No se encontró ese canal de EpicTV.");
    return found.raw;
  }
  return { home: home2, browse: browse2, search: search2, details: details2, episodes: episodes2, liveCategories: liveCategories2, liveChannels: liveChannels2, liveSearch: liveSearch2, channel };
}

// src/playback.mjs
var UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";
var MAX_COPIES = 9;
var MAX_LIVE_ATTEMPTS = 3;
var RECIPE_MAX_STEPS = 8;
var MIME = { hls: "application/vnd.apple.mpegurl", dash: "application/dash+xml", mp4: "video/mp4", ts: "video/mp2t" };
var FATAL = /* @__PURE__ */ new Set(["auth_required", "invalid_request", "cancelled"]);
var own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
var path = (url) => text(url).split(/[?#]/, 1)[0].toLowerCase();
var label = (value) => text(value).replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 48);
function mimeOf(url, kind = "") {
  const hint = text(kind).toLowerCase();
  if (MIME[hint]) return MIME[hint];
  if (["application/x-mpegurl", "audio/mpegurl", "audio/x-mpegurl"].includes(hint)) return MIME.hls;
  if (Object.values(MIME).includes(hint)) return hint;
  const p = path(url);
  if (/\.m3u8$/.test(p)) return MIME.hls;
  if (/\.mpd$/.test(p)) return MIME.dash;
  if (/\.mp4$/.test(p)) return MIME.mp4;
  if (/\.ts$/.test(p)) return MIME.ts;
  return "";
}
function language(value) {
  const s = text(value).trim().toLowerCase();
  if (/^[a-z]{2,3}(?:[-_][a-z0-9]{2,8})?$/.test(s)) return s.replace("_", "-");
  if (/espa[ñn]ol|spanish|castellano|latino/.test(s)) return "es";
  if (/ingl[eé]s|english/.test(s)) return "en";
  if (/portugu[eê]s|portuguese/.test(s)) return "pt";
  return "und";
}
function encodedUrlParameter(url, name) {
  const query = text(url).split("?", 2)[1]?.split("#", 1)[0] || "";
  for (const part of query.split("&")) {
    const at = part.indexOf("=");
    if (at < 0) continue;
    try {
      if (decodeURIComponent(part.slice(0, at).replace(/\+/g, " ")) === name) {
        return decodeURIComponent(part.slice(at + 1).replace(/\+/g, " "));
      }
    } catch (_) {
      return "";
    }
  }
  return "";
}
function decodeBase64(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const encoded = text(value).replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  if (!encoded || encoded.length > 12e3 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded) || encoded.replace(/=+$/, "").length % 4 === 1) return "";
  const bytes = [];
  let bits = 0, buffer = 0;
  for (const c of encoded.replace(/=+$/, "")) {
    buffer = buffer << 6 | alphabet.indexOf(c);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push(buffer >> bits & 255);
    }
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(bytes));
  } catch (_) {
    return "";
  }
}
function createPlayback({ kino, client, catalog }) {
  const fail = (code, message) => fault(kino, code, message);
  const unavailable = (message) => fail("unavailable", message);
  const timeLeft = (deadline, maximum = 12e3) => {
    const left = deadline - Date.now();
    if (left < 1e3) throw unavailable("La fuente tardó demasiado en responder.");
    return Math.min(left, maximum);
  };
  const address = (value, base) => {
    const input = text(value).trim();
    if (base === void 0 && !/^https?:\/\//i.test(input)) return "";
    return safeUrl(input, base);
  };
  function checkFormat(raw, url) {
    const drm = object(raw.drm);
    if (text(raw.key_id) || text(raw.key) || Object.keys(drm).length) {
      throw unavailable("Esta fuente requiere un tipo de licencia que esta integración no admite.");
    }
    const kind = text(raw.tipo || raw.mime || raw.formato).toLowerCase();
    if (/tiktik|png/.test(kind) || /\.png$/.test(path(url)) || /TIKTIK(?:PX|RAW|TSGZ)/i.test(text(raw.formato))) {
      throw unavailable("Esta fuente usa vídeo encapsulado PNG/TIKTIK y no es compatible con el reproductor de plugins.");
    }
  }
  async function stream(raw, options = {}) {
    const url = address(raw.url, options.base);
    if (!url) throw fail("not_found", "La fuente no contiene una dirección multimedia válida.");
    checkFormat(raw, url);
    const result = { url, headers: await client.mediaHeaders(url, object(raw.cabeceras || raw.headers)) };
    const mime = mimeOf(url, raw.tipo || raw.mime);
    if (mime) result.mime = mime;
    if (mime === MIME.hls && API_ORIGINS.includes(originOf(url))) {
      result.signing = "request";
      result.signContext = await client.signContext();
    }
    if (options.label) result.label = label(options.label);
    return result;
  }
  async function subtitles(rows, headers = {}) {
    const result = [], seen = /* @__PURE__ */ new Set();
    for (const row of array(rows)) {
      const item = object(row), url = address(item.url);
      if (!url || seen.has(url)) continue;
      seen.add(url);
      const sub = { url, lang: language(item.idioma || item.lang), label: text(item.idioma || item.label).slice(0, 60), headers: await client.mediaHeaders(url, headers) };
      const p = path(url);
      if (/\.srt$/.test(p)) sub.format = "srt";
      else if (/\.vtt$/.test(p)) sub.format = "vtt";
      else if (/\.(?:ass|ssa)$/.test(p)) sub.mime = "text/x-ssa";
      else if (/\.(?:ttml|dfxp)$/.test(p)) sub.mime = "application/ttml+xml";
      result.push(sub);
      if (result.length === 32) break;
    }
    return result;
  }
  async function vod(ref, deadline) {
    const params = { id: ref.id };
    if (ref.serie) params.serie = ref.serie;
    for (let attempt = 0; attempt < 2; attempt++) {
      const data = object(await client.get("/vod/play", params, { timeoutMs: timeLeft(deadline) }));
      if (data.ok === false || text(data.error)) throw unavailable("Epic no pudo preparar este vídeo.");
      const candidates = [data, ...array(data.alternativas)].map(object);
      const chosen = [], seen = /* @__PURE__ */ new Set();
      let unsupported = null, expired = false;
      for (const candidate of candidates) {
        const url = address(candidate.url);
        const copyKey = JSON.stringify([url, object(candidate.cabeceras || candidate.headers), text(candidate.tipo || candidate.mime)]);
        if (!url || seen.has(copyKey)) continue;
        const epoch = Number(candidate.caduca);
        const ttl = Number.isFinite(epoch) && epoch > 0 ? Math.floor(epoch - Date.now() / 1e3) : 0;
        if (epoch > 0 && ttl < 30) {
          expired = true;
          continue;
        }
        try {
          const name = ["Servidor " + (Number.isInteger(Number(candidate.servidor)) ? Number(candidate.servidor) : chosen.length + 1), candidate.respaldo ? "respaldo" : "", data.calidad, data.codec, data.audio].filter(Boolean).join(" · ");
          const source = await stream(candidate, { label: name });
          if (chosen.length && !chosen[0].source.signing && source.signing) continue;
          chosen.push({ source, ttl: ttl > 0 ? Math.min(ttl, 86400) : 0 });
          seen.add(copyKey);
        } catch (err) {
          if (err.code !== "unavailable") throw err;
          unsupported = err;
        }
        if (chosen.length === MAX_COPIES || chosen[0]?.source.signing) break;
      }
      if (!chosen.length) {
        if (expired && attempt === 0) continue;
        if (unsupported) throw unsupported;
        throw unavailable(expired ? "La autorización del vídeo ya venció. Vuelve a intentarlo." : "Epic no devolvió una copia reproducible.");
      }
      const result = chosen[0].source;
      if (chosen.length > 1) result.alternatives = chosen.slice(1).map((item) => item.source);
      const validTtls = chosen.map((item) => item.ttl).filter((value) => value > 0);
      if (validTtls.length) result.expiresInSeconds = Math.min(...validTtls);
      const tracks = await subtitles(data.subtitulos_url, { "User-Agent": "MisStreams" });
      if (tracks.length) result.subtitles = tracks;
      return result;
    }
    throw unavailable("La autorización del vídeo no pudo renovarse.");
  }
  async function browser(source, deadline) {
    if (!kino.browser || typeof kino.browser.capture !== "function") throw unavailable("Esta fuente necesita el navegador de reproducción, que no está disponible.");
    const url = address(source.url);
    if (!url) throw fail("not_found", "La página de esta fuente no es válida.");
    const result = object(await kino.browser.capture(url, {
      timeoutMs: timeLeft(deadline, 15e3),
      autoplay: true,
      headers: { "User-Agent": UA }
    }));
    for (const candidate of array(result.media)) {
      try {
        const playback = await stream(object(candidate));
        const tracks = await subtitles(result.subtitles);
        if (tracks.length) playback.subtitles = tracks;
        return playback;
      } catch (err) {
        if (!["unavailable", "not_found"].includes(err.code)) throw err;
      }
    }
    throw unavailable("La página no ofreció un vídeo compatible.");
  }
  function recipePattern(value) {
    const pattern = text(value);
    if (!pattern || pattern.length > 400 || /\\[1-9]|\(\?[=!<]|\)[+*{]|(?:\.\*){2}/.test(pattern)) {
      throw unavailable("La receta requiere un patrón que esta integración no admite.");
    }
    try {
      return new RegExp(pattern);
    } catch (_) {
      throw unavailable("La receta contiene un patrón incompatible.");
    }
  }
  function validateRecipe(recipe2) {
    const steps = array(recipe2.pasos);
    if (!steps.length || steps.length > RECIPE_MAX_STEPS) throw unavailable("La receta no tiene una secuencia compatible.");
    const allowed = /* @__PURE__ */ new Set(["pide", "cuerpo", "metodo", "campo", "guarda", "cabeceras", "busca", "base64", "opcional", "pagina", "raspa", "sigue", "saltos", "desenvuelve"]);
    return steps.map((value) => {
      const step = object(value);
      if (!Object.keys(step).length || Object.keys(step).some((k) => !allowed.has(k))) throw unavailable("Esta receta requiere operaciones que esta integración todavía no admite.");
      const actions = [own(step, "pide"), !!text(step.busca), !!text(step.base64), !!text(step.raspa)].filter(Boolean).length;
      if (actions !== 1) throw unavailable("La receta combina pasos que esta integración no admite.");
      const fields = own(step, "pide") ? ["pide", "cuerpo", "metodo", "campo", "guarda", "cabeceras"] : text(step.busca) ? ["busca", "cabeceras"] : text(step.raspa) ? ["raspa", "sigue", "saltos", "desenvuelve", "cabeceras"] : ["base64", "opcional", "pagina"];
      if (Object.keys(step).some((key) => !fields.includes(key))) throw unavailable("La receta combina opciones que esta integración no admite.");
      if (own(step, "opcional") && typeof step.opcional !== "boolean") throw unavailable("La receta contiene una opción inválida.");
      if (own(step, "pagina") && typeof step.pagina !== "boolean") throw unavailable("La receta contiene una opción de página inválida.");
      if (own(step, "saltos") && !Number.isInteger(step.saltos)) throw unavailable("La receta contiene un límite de páginas inválido.");
      if (own(step, "cabeceras") && (typeof step.cabeceras !== "object" || step.cabeceras === null || Array.isArray(step.cabeceras))) throw unavailable("La receta contiene cabeceras inválidas.");
      if (Object.values(object(step.cabeceras)).some((value2) => typeof value2 !== "string")) throw unavailable("La receta contiene una cabecera inválida.");
      for (const key of ["pide", "cuerpo", "metodo", "campo", "guarda", "busca", "base64", "raspa", "sigue", "desenvuelve"]) {
        if (own(step, key) && typeof step[key] !== "string") throw unavailable("La receta contiene un paso inválido.");
      }
      const method = text(step.metodo).toUpperCase();
      if (method && !["GET", "POST"].includes(method)) throw unavailable("El método de esta receta no está admitido.");
      if (text(step.busca)) recipePattern(step.busca);
      if (text(step.raspa)) recipePattern(step.raspa);
      if (text(step.sigue)) recipePattern(step.sigue);
      if (text(step.guarda) && !/^[A-Za-z0-9_-]{1,64}$/.test(step.guarda)) throw unavailable("La receta contiene una variable inválida.");
      return step;
    });
  }
  async function recipe(source, deadline) {
    let definition = object(source.receta);
    if (!Object.keys(definition).length && text(source.receta_id)) {
      const response = object(await client.get("/receta", { id: source.receta_id }, { timeoutMs: timeLeft(deadline) }));
      definition = object(response.receta);
    }
    const steps = validateRecipe(definition);
    const vars = /* @__PURE__ */ Object.create(null);
    const substitute = (value) => text(value).replace(/\{([A-Za-z0-9_-]+)\}/g, (whole, name) => own(vars, name) ? vars[name] : whole);
    let current = address(source.url);
    const referer = address(definition.ref) || originOf(current) + "/";
    let mediaReferer = referer;
    if (!current) throw fail("not_found", "La dirección inicial de la receta no es válida.");
    checkFormat(definition, current);
    if (typeof client.fetchExternal !== "function") throw unavailable("El transporte de recetas no está disponible.");
    const readPage = async (target, step, pageReferer) => {
      const headers = { "User-Agent": UA, Referer: pageReferer, Accept: "*/*" };
      for (const [key, value] of Object.entries(object(step.cabeceras))) headers[key] = substitute(value);
      const options = { method: text(step.metodo).toUpperCase() || (own(step, "cuerpo") ? "POST" : "GET"), headers, timeoutMs: timeLeft(deadline, 6e3) };
      if (own(step, "cuerpo")) options.body = substitute(step.cuerpo);
      const response = await client.fetchExternal(target, options);
      if ([401, 403].includes(Number(response && response.status))) throw fail("auth_required", "La fuente no autorizó esta reproducción.");
      if (response && Number(response.status) >= 400) throw unavailable("La página de la receta rechazó la petición.");
      const body = typeof response === "string" ? response : await response.text();
      if (body.length > 1024 * 1024) throw unavailable("La respuesta de la receta es demasiado grande.");
      return body;
    };
    for (const step of steps) {
      let output = "";
      if (text(step.base64)) {
        output = address(decodeBase64(encodedUrlParameter(current, step.base64)));
        if (!output && step.opcional) continue;
      } else if (text(step.raspa)) {
        const extract = recipePattern(step.raspa), follow = text(step.sigue) ? recipePattern(step.sigue) : null;
        const jumps = Math.max(0, Math.min(6, own(step, "saltos") ? step.saltos : 3));
        let page = current, pageReferer = referer;
        const visited = /* @__PURE__ */ new Set();
        for (let jump = 0; jump <= jumps; jump++) {
          if (text(step.desenvuelve)) page = address(decodeBase64(encodedUrlParameter(page, step.desenvuelve))) || page;
          if (visited.has(page)) break;
          visited.add(page);
          const body = (await readPage(page, step, pageReferer)).replace(/\\u0026/g, "&");
          const found = extract.exec(body);
          if (found) {
            output = address(text(found[1] || found[0]));
            if (!address(definition.ref)) mediaReferer = originOf(page) + "/";
            break;
          }
          const nextMatch = follow && follow.exec(body);
          if (!nextMatch || jump === jumps) break;
          const next = address(text(nextMatch[1] || nextMatch[0]), originOf(page) + "/");
          if (!next || next === page) break;
          page = next;
          pageReferer = originOf(next) + "/";
        }
      } else {
        const target = own(step, "pide") ? address(substitute(step.pide) || current, current) : current;
        if (!target) throw unavailable("La receta solicita una dirección no válida.");
        const body = await readPage(target, step, referer);
        if (text(step.busca)) {
          const match = recipePattern(step.busca).exec(body);
          output = match ? text(match[1] || match[0]).replace(/&amp;/g, "&").replace(/\\\//g, "/").replace(/\\u0026/g, "&").trim() : "";
        } else if (text(step.campo)) {
          let value;
          try {
            value = JSON.parse(body);
          } catch (_) {
            throw unavailable("La receta esperaba una respuesta JSON.");
          }
          for (const key of step.campo.split(".")) value = value && typeof value === "object" && own(value, key) ? value[key] : null;
          output = typeof value === "string" || typeof value === "number" ? String(value) : "";
        } else output = body.trim();
        if (text(step.guarda) && output) {
          vars[step.guarda] = output;
          continue;
        }
        output = address(output, target);
      }
      if (!output) throw unavailable("La receta no encontró la dirección de reproducción.");
      current = output;
    }
    if (!mimeOf(current, definition.tipo)) throw unavailable("La receta no devolvió un formato multimedia identificado.");
    return stream({ url: current, tipo: definition.tipo, cabeceras: { "User-Agent": UA, Referer: mediaReferer } });
  }
  async function resolveSource(source, deadline) {
    const url = address(source.url);
    if (!url) throw fail("not_found", "La fuente del canal no tiene una dirección válida.");
    checkFormat(source, url);
    const mode = text(source.mode) || "local";
    if (mode === "uefa") throw unavailable("Esta fuente usa el flujo DICE/DRM, que no está incluido en esta integración.");
    if (mode === "receta" || mode === "local" && (Object.keys(object(source.receta)).length || text(source.receta_id))) return recipe(source, deadline);
    if (mode === "navegador" || mode === "webview" || mode === "local") return browser(source, deadline);
    const resolved = object(await client.get("/resolve", { url }, { timeoutMs: timeLeft(deadline) }));
    if (text(resolved.error)) throw unavailable("Epic no pudo resolver esta fuente del canal.");
    const media = address(resolved.stream);
    if (!media) throw unavailable("Epic no devolvió un enlace multimedia para este canal.");
    checkFormat(resolved, media);
    if (mode === "directo") {
      const headers = { "User-Agent": text(resolved.ua) || UA };
      const ref = address(resolved.ref), origin = originOf(address(resolved.origin));
      if (ref) headers.Referer = ref;
      if (origin) headers.Origin = origin;
      return stream({ url: media, tipo: resolved.tipo, cabeceras: headers });
    }
    let proxy = client.origin().replace(/\/$/, "") + "/proxy?url=" + encodeURIComponent(media);
    if (text(resolved.ref)) proxy += "&ref=" + encodeURIComponent(resolved.ref);
    if (text(resolved.auth)) proxy += "&auth=" + encodeURIComponent(resolved.auth);
    return stream({ url: proxy, tipo: resolved.tipo || mimeOf(media) });
  }
  async function resolveChannel(channelRaw, options = {}) {
    const channel = object(channelRaw);
    const deadline = Math.min(Number(options.deadline) || Date.now() + 55e3, Date.now() + 55e3);
    if (!Object.keys(channel).length) throw fail("not_found", "Este canal ya no está disponible en el catálogo.");
    const sources = [channel, ...array(channel.respaldos).map(object)], seen = /* @__PURE__ */ new Set();
    let attempts = 0, lastError = null;
    for (const source of sources) {
      const key = JSON.stringify([text(source.url), text(source.mode) || "local", text(source.receta_id), object(source.receta)]);
      if (!text(source.url) || seen.has(key)) continue;
      seen.add(key);
      if (++attempts > MAX_LIVE_ATTEMPTS) break;
      try {
        return await resolveSource(source, deadline);
      } catch (err) {
        if (FATAL.has(err.code) || err.status === 401 || err.status === 403) throw err;
        lastError = err;
      }
    }
    throw lastError || unavailable("El canal no contiene una fuente de reproducción compatible.");
  }
  async function resolve2(input) {
    const original = typeof input === "string" ? input : text(object(input).ref);
    const ref = object(decodeRef(original));
    const deadline = Date.now() + 55e3;
    if (ref.kind === "live") {
      if (!text(ref.id)) throw fail("invalid_request", "La referencia del canal no es válida.");
      return resolveChannel(await catalog.channel(original), { deadline });
    }
    if (!["movie", "episode"].includes(ref.kind) || !/^[a-f0-9]{32}$/i.test(text(ref.id)) || ref.serie && !/^[a-f0-9]{32}$/i.test(text(ref.serie))) {
      throw fail("invalid_request", "La referencia de reproducción no es válida.");
    }
    return vod(ref, deadline);
  }
  return { resolve: resolve2, resolveChannel };
}

// src/events.mjs
var PUBLIC_ID2 = /^[A-Za-z0-9._~-]{1,128}$/;
var MENU_TTL = 3e4;
var PAGE_SIZE = 200;
var MAX_EVENTS = 500;
var MAX_LINKS = 20;
var DEFAULT_ZONE = "America/Lima";
var MODES = {
  "raspar-local": "local",
  "raspar-receta": "receta",
  "resolver-directo": "directo",
  "raspar-navegador": "navegador",
  "resolver-proxy": "proxy",
  webview: "webview",
  uefa: "uefa"
};
var record2 = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
var string2 = (value) => typeof value === "string" ? value.trim() : typeof value === "number" && Number.isFinite(value) ? String(value) : "";
var list2 = (value) => Array.isArray(value) ? value : [];
var clean = (value, length) => string2(value).replace(/[\u0000-\u001f\u007f]/g, "").slice(0, length);
function validDate(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(string2(value));
  if (!match) return "";
  const year = Number(match[1]), month = Number(match[2]), day = Number(match[3]);
  if (year < 1970 || month < 1 || month > 12) return "";
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day > 0 && day <= days[month - 1] ? match[0] : "";
}
function timeOf(raw, rootDate) {
  const sourceDate = string2(raw.date) || string2(rootDate);
  const date = validDate(sourceDate);
  const match = /^(\d{1,2}):(\d{2})$/.exec(string2(raw.hour));
  if (!date || !match || Number(match[1]) > 23 || Number(match[2]) > 59) return null;
  return { date, startsAt: `${date}T${match[1].padStart(2, "0")}:${match[2]}:00-05:00` };
}
function statusOf(raw) {
  const suspended = string2(raw.suspendido).toLowerCase();
  if (suspended === "aplazado") return "postponed";
  if (["cancelado", "cancelada"].includes(suspended)) return "cancelled";
  if (["terminó", "terminado", "finalizado"].includes(suspended) || raw.ended === true) return "ended";
  const status = string2(raw.status).toLowerCase();
  if (["upcoming", "live", "ended", "postponed", "cancelled"].includes(status)) return status;
  const clock = record2(raw.reloj) ? string2(raw.reloj.estado).toLowerCase() : "";
  if (["terminado", "finalizado"].includes(clock)) return "ended";
  if (clock === "aplazado") return "postponed";
  if (clock === "cancelado") return "cancelled";
  return "";
}
function createEvents({ kino, client, playback }) {
  const fail = (code, message) => {
    throw fault(kino, code, message);
  };
  const hash = (value) => kino.crypto.hash("sha256", value);
  const country = () => {
    const value = string2(kino.config?.get("country")).toUpperCase();
    return /^[A-Z]{2}$/.test(value) ? value : "";
  };
  const image = (value) => {
    const url = safeUrl(value, client.origin());
    return url.length <= 2048 && /^https:\/\//i.test(url) ? url : "";
  };
  function context(args = {}) {
    if (!record2(args)) args = {};
    const date = string2(args.date);
    const timeZone = string2(args.timeZone) || DEFAULT_ZONE;
    if (date && !validDate(date) || timeZone.length > 64 || !/^[A-Za-z][A-Za-z0-9_+-]*(?:\/[A-Za-z0-9_+-]+){0,2}$/.test(timeZone)) {
      fail("invalid_request", "La fecha o zona horaria solicitada no es válida.");
    }
    return { date, timeZone };
  }
  function menu(ctx) {
    const region = country();
    return client.cached(`events:menu:${ctx.timeZone}:${region}`, MENU_TTL, async () => {
      const result = await client.get("/menu", { all: "1", recetas: "aparte", tz: ctx.timeZone, ...region ? { pais_elegido: region } : {} });
      if (!record2(result) || result.ok === false || result.activo === false) fail("unavailable", "EpicTV no pudo entregar la agenda de eventos.");
      if (!Array.isArray(result.events)) fail("unavailable", "La agenda de EpicTV tiene un formato inesperado.");
      return result;
    });
  }
  function identity(raw, time) {
    const id = string2(raw.id);
    return PUBLIC_ID2.test(id) ? id : "e-" + hash(JSON.stringify([id, time.date, time.startsAt, string2(raw.titulo) || string2(raw.description)])).slice(0, 40);
  }
  function entries(body) {
    const seen = /* @__PURE__ */ new Set(), result = [];
    for (const raw of body.events) {
      if (!record2(raw) || raw.oculto === true || !(string2(raw.titulo) || string2(raw.description))) continue;
      const time = timeOf(raw, body.date);
      if (!time) continue;
      const id = identity(raw, time);
      if (seen.has(id)) continue;
      seen.add(id);
      result.push({ id, raw, ...time });
    }
    return result;
  }
  function category(raw, type) {
    const source = type === "sport" ? raw.deporte : raw.filtro_liga;
    if (!record2(source) || !string2(source.clave) || !string2(source.nombre)) return null;
    return { id: (type === "sport" ? "s-" : "l-") + hash(JSON.stringify([string2(source.clave), type === "league" ? string2(source.grupo) : ""])).slice(0, 32), title: clean(source.nombre, 30) };
  }
  function participants(raw, title, competition) {
    const names = title.split(/\s+vs\.?\s+/i);
    if (names.length !== 2 || names.some((name) => !name.trim())) return [];
    const colon = names[0].indexOf(":");
    if (colon > 0 && names[0].slice(0, colon).trim().toLowerCase() === competition.toLowerCase()) names[0] = names[0].slice(colon + 1).trim();
    if (names.some((name) => !name.trim())) return [];
    const score = /^\s*(\d{1,4})\s*[-–:]\s*(\d{1,4})\s*$/.exec(string2(raw.marcador) || string2(record2(raw.reloj) ? raw.reloj.marcador : ""));
    return names.map((name, index) => {
      const participant = { name: clean(name, 80) };
      const logo = image(index === 0 ? raw.escudo_local : raw.escudo_visitante);
      if (logo) participant.logo = logo;
      if (score) participant.score = Number(score[index + 1]);
      return participant;
    });
  }
  function project(entry, ctx, allowedCategories) {
    const { id, raw, date, startsAt } = entry;
    const title = clean(string2(raw.titulo) || string2(raw.description), 200);
    const result = { id, title, startsAt, ref: encodeRef("event", { id, date, timeZone: ctx.timeZone }) };
    const competition = clean(record2(raw.filtro_liga) ? raw.filtro_liga.nombre || raw.liga : raw.liga, 80);
    if (competition) result.competition = competition;
    const competitionLogo = image(raw.liga_logo);
    if (competitionLogo) result.competitionLogo = competitionLogo;
    const sport = clean(record2(raw.deporte) ? raw.deporte.nombre : "", 40);
    if (sport) result.sport = sport;
    const location = clean(raw.pais_es || raw.country || raw.pais, 40);
    if (location) result.country = location;
    const members = participants(raw, string2(raw.titulo) || string2(raw.description), competition);
    if (members.length) result.participants = members;
    const status = statusOf(raw);
    if (status) result.status = status;
    if (status === "live") {
      const minuteRaw = record2(raw.reloj) && raw.reloj.minuto != null ? raw.reloj.minuto : raw.minute;
      const minute = Number(minuteRaw);
      const phase = clean(raw.phase, 24);
      if (phase) result.statusText = phase;
      else if (string2(minuteRaw) && Number.isInteger(minute) && minute >= 0 && minute <= 999) result.statusText = `${minute}'`;
    }
    const note = clean(record2(raw.aviso) ? raw.aviso.titulo || raw.aviso.texto : raw.ronda, 120);
    if (note) result.note = note;
    if (raw.destacado === true) {
      result.featured = true;
      const highlight = clean(raw.realce, 20);
      if (highlight) result.featuredLabel = highlight;
    }
    const categories = ["sport", "league"].map((type) => category(raw, type)).filter((value) => value && allowedCategories.has(value.id)).map((value) => value.id);
    if (categories.length) result.categories = categories;
    return result;
  }
  async function events2(args = {}) {
    const ctx = context(args);
    const contextId = hash(JSON.stringify([ctx.date, ctx.timeZone, country()]));
    let offset = 0;
    if (args?.cursor != null && args.cursor !== "") {
      if (typeof args.cursor !== "string" || args.cursor.length > 2048) fail("not_found", "La página de eventos no es válida.");
      const state = decodeRef(args.cursor);
      if (state.kind !== "events-page" || state.context !== contextId || !Number.isInteger(state.offset) || state.offset < 0 || state.offset >= MAX_EVENTS) {
        fail("not_found", "La página solicitada no corresponde a esta agenda.");
      }
      offset = state.offset;
    }
    const all = entries(await menu(ctx)).slice(0, MAX_EVENTS);
    const known = /* @__PURE__ */ new Map();
    for (const type of ["sport", "league"]) for (const { raw } of all) {
      const value = category(raw, type);
      if (value && !known.has(value.id) && known.size < 30) known.set(value.id, value);
    }
    const result = { items: all.slice(offset, offset + PAGE_SIZE).map((entry) => project(entry, ctx, known)), categories: [...known.values()], refreshSeconds: 30 };
    if (offset + PAGE_SIZE < all.length) result.next = encodeRef("events-page", { context: contextId, offset: offset + PAGE_SIZE });
    return result;
  }
  function sourceRows(raw) {
    const seen = /* @__PURE__ */ new Set(), sources = [];
    for (const group of list2(raw.cocinas)) {
      if (!record2(group) || !Object.prototype.hasOwnProperty.call(MODES, string2(group.modo))) continue;
      for (const source of list2(group.canales)) {
        if (!record2(source) || !/^https?:\/\//i.test(string2(source.url)) || !safeUrl(source.url)) continue;
        const channel = {
          ...source,
          mode: MODES[string2(group.modo)],
          cocina: string2(group.fuente),
          ...record2(group.receta) ? { receta: group.receta } : {},
          ...string2(group.receta_id) ? { receta_id: string2(group.receta_id) } : {}
        };
        const stable = hash(JSON.stringify([string2(source.id), string2(source.name), channel.mode, channel.cocina, string2(group.receta_id), string2(source.url).split(/[?#]/)[0]]));
        if (seen.has(stable)) continue;
        seen.add(stable);
        sources.push({ id: stable, channel });
      }
    }
    return sources.sort((a, b) => Number(b.channel.prioridad === true) - Number(a.channel.prioridad === true));
  }
  async function lookup(ref, kind) {
    const selected = decodeRef(ref);
    if (selected.kind !== kind || !PUBLIC_ID2.test(string2(selected.id)) || !validDate(selected.date)) fail("not_found", "El evento solicitado no es válido.");
    const ctx = context(selected);
    const entry = entries(await menu(ctx)).find((value) => value.id === selected.id && value.date === selected.date);
    if (!entry) fail("not_found", "Este evento ya no está disponible en la agenda de EpicTV.");
    return { selected, entry };
  }
  async function eventLinks2(ref) {
    const { selected, entry } = await lookup(ref, "event");
    return { links: sourceRows(entry.raw).slice(0, MAX_LINKS).map(({ id, channel }, index) => {
      const link = {
        name: clean(channel.publico || channel.name, 60) || `Servidor ${index + 1}`,
        ref: encodeRef("event-link", { id: entry.id, date: entry.date, timeZone: selected.timeZone, source: id })
      };
      if (channel.prioridad === true) link.top = true;
      const quality = clean(channel.calidad || channel.quality, 20);
      const language2 = clean(channel.idioma || channel.language, 24);
      if (quality) link.quality = quality;
      if (language2) link.language = language2;
      return link;
    }) };
  }
  async function resolve2(ref, options = {}) {
    const { selected, entry } = await lookup(ref, "event-link");
    if (!/^[a-f0-9]{64}$/i.test(string2(selected.source))) fail("not_found", "El servidor solicitado no es válido.");
    const source = sourceRows(entry.raw).find((value) => value.id === selected.source);
    if (!source) fail("not_found", "Este servidor ya no está disponible para el evento.");
    return playback.resolveChannel(source.channel, options);
  }
  return { events: events2, eventLinks: eventLinks2, resolve: resolve2 };
}

// src/index.mjs
var instance;
function services() {
  if (!instance) {
    const kino = globalThis.zuper;
    const client = createClient(kino);
    const catalog = createCatalog({ kino, client });
    const playback = createPlayback({ kino, client, catalog });
    const agenda = createEvents({ kino, client, playback });
    instance = { kino, client, catalog, playback, agenda };
  }
  return instance;
}
var home = () => services().catalog.home();
var browse = (ref, cursor) => services().catalog.browse(ref, cursor);
var search = (query) => services().catalog.search(query);
var details = (ref) => services().catalog.details(ref);
var episodes = (ref) => services().catalog.episodes(ref);
var liveCategories = () => services().catalog.liveCategories();
var liveChannels = (args) => services().catalog.liveChannels(args);
var liveSearch = (args) => services().catalog.liveSearch(args);
var events = (args) => services().agenda.events(args);
var eventLinks = (ref) => services().agenda.eventLinks(ref);
function resolve(ref, options) {
  const current = services();
  const kind = decodeRef(ref).kind;
  return kind === "event-link" ? current.agenda.resolve(ref, options) : current.playback.resolve(ref, options);
}
var sign = (request) => ({ headers: services().client.signedHeaders(object(request).url, object(request).context) });
var settingsStatus = () => ({ status: services().client.status() });
async function action(key) {
  if (key !== "reconnect") throw fault(services().kino, "invalid_request", "Acción no disponible.");
  await services().client.reconnect();
  return { message: "Instalación conectada" };
}
function validateSettings(values = {}) {
  const config = object(values);
  const key = text(config.apiKey).trim();
  const country = text(config.country).trim();
  if (key && !/^[\x21-\x7e]{32}$/.test(key)) return { apiKey: "La clave debe tener 32 caracteres, sin espacios." };
  if (country && !/^[a-z]{2}$/i.test(country)) return { country: "Introduce dos letras, como CO o MX, o déjalo vacío." };
  return null;
}
export {
  action,
  browse,
  details,
  episodes,
  eventLinks,
  events,
  home,
  liveCategories,
  liveChannels,
  liveSearch,
  resolve,
  search,
  settingsStatus,
  sign,
  validateSettings
};
