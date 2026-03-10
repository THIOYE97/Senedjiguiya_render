// ================================================
// 🚀 SERVER - Senedjiguiya API (optimisé)
// ================================================

import express from "express";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import compression from "compression";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import { parse } from "pg-connection-string";
import crypto from "crypto";

dotenv.config();

// ================================================
// 🛡️ Gestion globale des erreurs
// ================================================
process.on("unhandledRejection", (err) => console.error("🚨 Promise non gérée:", err?.message));
process.on("uncaughtException",  (err) => { console.error("💥 Erreur fatale:", err?.message); process.exit(1); });

const { Pool } = pkg;
const IS_PROD = process.env.NODE_ENV === "production";

// ================================================
// 🗄️ Pool PostgreSQL — optimisé Supabase/Render
// ================================================
if (!process.env.DATABASE_URL) {
  console.error("❌ DATABASE_URL manquant dans .env !");
  process.exit(1);
}

const parsed = parse(process.env.DATABASE_URL);

console.log("🔍 DB host:", parsed.host);
console.log("🔍 DB port:", parsed.port);
console.log("🔍 DB name:", parsed.database);

const db = new Pool({
  host:     parsed.host,
  port:     Number(parsed.port) || 5432,
  user:     parsed.user,
  password: parsed.password,
  database: parsed.database,
  ssl:               { rejectUnauthorized: false },
  max:               5,
  min:               1,
  idleTimeoutMillis:        60_000,
  connectionTimeoutMillis:  10_000,  // augmenté pour Supabase cold start
  statement_timeout:        15_000,
  keepAlive:                true,
  keepAliveInitialDelayMillis: 10_000,
});

export { db };

db.on("error", (err) => console.error("🚨 Pool PostgreSQL:", err.message));

// Test initial de connexion (sans boucle infinie)
(async () => {
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      const client = await db.connect();
      client.release();
      console.log("✅ PostgreSQL connecté");
      return;
    } catch (err) {
      console.error(`⚠️ Tentative ${attempt}/5 — ${err.message}`);
      if (attempt < 5) await sleep(attempt * 2000);
    }
  }
  console.error("❌ Impossible de se connecter à la DB après 5 tentatives.");
})();

// Ping toutes les 4 min pour éviter idle disconnect
setInterval(() => db.query("SELECT 1").catch(() => {}), 4 * 60_000);

// ================================================
// ⚡ CACHE EN MÉMOIRE (permissions + paquets)
// ================================================

/**
 * Cache générique TTL
 * Clé → { value, expiresAt }
 */
class TTLCache {
  constructor(ttlMs = 60_000) {
    this._store = new Map();
    this._ttl   = ttlMs;
  }
  get(key) {
    const entry = this._store.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) { this._store.delete(key); return undefined; }
    return entry.value;
  }
  set(key, value) {
    this._store.set(key, { value, expiresAt: Date.now() + this._ttl });
  }
  del(key) { this._store.delete(key); }
  clear()  { this._store.clear(); }
}

const permCache  = new TTLCache(5 * 60_000);   // permissions → 5 min
const paquetCache = new TTLCache(10 * 60_000);  // paquets → 10 min (données statiques)

// ================================================
// 🌐 Express — middlewares globaux
// ================================================
const app = express();

app.use(compression());                             // ✅ Gzip sur toutes les réponses JSON
app.use(express.json({ limit: "100kb" }));          // Limite payload
app.use(cors({ origin: "*" }));

// ================================================
// 🔒 Rate limiting
// ================================================

const loginLimiter = rateLimit({
  windowMs: 15 * 60_000,  // 15 min
  max: 20,
  message: { message: "Trop de tentatives. Réessayez dans 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

const paiementLimiter = rateLimit({
  windowMs: 60_000,  // 1 min
  max: 30,
  message: { message: "Trop de requêtes." },
  // ✅ userId si authenifié (pas d'IPv6 concern), sinon ipKeyGenerator pour IPv4/IPv6
  keyGenerator: (req) => req.user?.id ? String(req.user.id) : ipKeyGenerator(req),
});

// ================================================
// 🔑 AUTH — JWT
// ================================================

function authenticateToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token manquant" });

  jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] }, (err, user) => {
    if (err) return res.status(403).json({ message: "Token invalide ou expiré" });
    req.user = user;
    next();
  });
}

// ================================================
// 🛡️ PERMISSIONS — avec cache
// ================================================

async function hasPermission(role, permissionName) {
  const cacheKey = `${role}:${permissionName}`;
  const cached = permCache.get(cacheKey);
  if (cached !== undefined) return cached;

  const { rows } = await db.query(
    `SELECT 1
     FROM roles r
     JOIN roles_permissions rp ON r.id  = rp.role_id
     JOIN permissions p         ON p.id  = rp.permission_id
     WHERE r.name = $1 AND p.name = $2
     LIMIT 1`,
    [role, permissionName]
  );
  const result = rows.length > 0;
  permCache.set(cacheKey, result);
  return result;
}

function requirePermission(permissionName) {
  return async (req, res, next) => {
    try {
      const allowed = await hasPermission(req.user.role, permissionName);
      if (!allowed) return res.status(403).json({ message: "Accès interdit" });
      next();
    } catch (e) {
      console.error("requirePermission:", e.message);
      res.status(500).json({ message: "Erreur serveur" });
    }
  };
}

// ================================================
// 🔄 IDEMPOTENCY — version robuste (sans monkey-patch)
// ================================================

function stableStringify(obj) {
  if (obj === null || obj === undefined) return "null";
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(stableStringify).join(",")}]`;
  return `{${Object.keys(obj).sort().map(k => `"${k}":${stableStringify(obj[k])}`).join(",")}}`;
}

function hashBody(body) {
  return crypto.createHash("sha256").update(stableStringify(body)).digest("hex");
}

/**
 * Wrapper d'idempotence refactorisé :
 * - handler() renvoie { status, body } au lieu de manipuler res directement
 * - on stocke le résultat APRÈS l'exécution
 */
async function withIdempotency(req, res, routeName, handler) {
  const key = req.header("X-Idempotency-Key");
  if (!key) return handler(res); // pas de clé → exécution normale

  const userId      = req.user?.id ?? 0;
  const requestHash = hashBody(req.body);

  try {
    const { rows } = await db.query(
      `SELECT response_code, response_body, request_hash
       FROM idempotency_keys
       WHERE key = $1 AND user_id = $2 AND route = $3
       LIMIT 1`,
      [key, userId, routeName]
    );

    if (rows.length > 0) {
      const row = rows[0];
      if (row.request_hash !== requestHash) {
        return res.status(409).json({ message: "Idempotency key réutilisée avec un contenu différent." });
      }
      return res.status(row.response_code).json(row.response_body);
    }
  } catch (e) {
    console.warn("Idempotency lookup:", e.message);
    return handler(res); // fail-open
  }

  // Créer une version "intercepteur" légère du res pour capturer status + body
  let capturedStatus = 200;
  const originalStatus = res.status.bind(res);
  const originalJson   = res.json.bind(res);

  res.status = (code) => { capturedStatus = code; return res; };
  res.json   = async (body) => {
    // Restaurer avant d'écrire
    res.status = originalStatus;
    res.json   = originalJson;

    // Sauvegarder en base (best-effort, non-bloquant)
    db.query(
      `INSERT INTO idempotency_keys (key, user_id, route, request_hash, response_code, response_body)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (key, user_id, route) DO NOTHING`,
      [key, userId, routeName, requestHash, capturedStatus, JSON.stringify(body)]
    ).catch(e => console.warn("Idempotency save:", e.message));

    return originalStatus(capturedStatus).json(body) ?? originalJson(body);
  };

  return handler(res);
}

// ================================================
// 🛠️ UTILITAIRES
// ================================================

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/**
 * Vérification du reçu en doublon : centralisée ici
 */
async function checkRecuLimit(client, numero_recu, montant) {
  const { rows } = await client.query(
    "SELECT COUNT(*)::int AS cnt FROM paiements WHERE numero_recu = $1 AND montant = $2",
    [numero_recu.trim(), montant]
  );
  return rows[0].cnt;
}

// ================================================
// 📋 ROUTES
// ================================================

// --- Health check ---
app.get("/", (_req, res) => res.json({ status: "ok", ts: Date.now() }));

// ==================== REGISTER ====================

app.post(
  "/register",
  authenticateToken,
  requirePermission("manage_users"),
  async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password || !role)
      return res.status(400).json({ message: "Champs manquants" });

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.query(
        "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)",
        [username, hashedPassword, role]
      );
      res.json({ message: "Utilisateur créé avec succès" });
    } catch (err) {
      if (err.code === "23505")
        return res.status(409).json({ message: "Ce nom d'utilisateur existe déjà." });
      console.error("POST /register:", err.message);
      res.status(500).json({ message: "Erreur serveur" });
    }
  }
);

// ==================== LOGIN ====================

app.post("/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: "Champs manquants" });

  try {
    const { rows } = await db.query("SELECT * FROM users WHERE username = $1", [username]);
    // ✅ On fait quand même bcrypt même si user introuvable (résistance aux timing attacks)
    const fakeHash = "$2b$10$invalidhashpaddingtomakeitlookreal00000000000000000";
    const user     = rows[0];
    const match    = await bcrypt.compare(password, user?.password_hash ?? fakeHash);

    if (!user || !match)
      return res.status(400).json({ message: "Identifiants incorrects" });

    let ve_id = null, village_id = null;

    if (user.role === "VE") {
      const veRes = await db.query(
        "SELECT id, village_id FROM ve WHERE user_id = $1 LIMIT 1",
        [user.id]
      );
      if (veRes.rows.length > 0) {
        ve_id      = veRes.rows[0].id;
        village_id = veRes.rows[0].village_id;
      }
    }

    const token = jwt.sign(
      { id: user.id, role: user.role, ve_id, village_id },
      process.env.JWT_SECRET,
      { expiresIn: "30d", algorithm: "HS256" }
    );

    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role, ve_id, village_id },
    });
  } catch (err) {
    console.error("POST /login:", err.message);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// ==================== ME ====================

app.get("/me", authenticateToken, async (req, res) => {
  try {
    const { rows } = await db.query(
      "SELECT id, username, role FROM users WHERE id = $1",
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ message: "Utilisateur introuvable" });
    res.json({ user: rows[0] });
  } catch (err) {
    console.error("GET /me:", err.message);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// ==================== VE LIST ====================

app.get("/ve", authenticateToken, async (req, res) => {
  try {
    if (req.user.role === "ADMIN") {
      // ✅ Une seule requête agrégée (était déjà bien)
      const { rows } = await db.query(`
        SELECT
          ve.id, ve.ve_code, ve.nom, ve.prenom,
          vil.nom_village,
          u.username AS user_account,
          COALESCE(c_count.nb_inscrits,          0) AS nb_inscrits,
          COALESCE(p_sum.total_paiements,         0) AS total_paiements,
          COALESCE(paq_sum.total_valeur_paquets,  0) AS total_valeur_paquets
        FROM ve
        LEFT JOIN villages vil ON ve.village_id = vil.id
        LEFT JOIN users    u   ON ve.user_id    = u.id
        LEFT JOIN (
          SELECT ve_id, COUNT(DISTINCT id)::int AS nb_inscrits FROM clients GROUP BY ve_id
        ) c_count   ON c_count.ve_id  = ve.id
        LEFT JOIN (
          SELECT c.ve_id, SUM(p.montant) AS total_paiements
          FROM paiements p JOIN clients c ON p.client_id = c.id GROUP BY c.ve_id
        ) p_sum     ON p_sum.ve_id    = ve.id
        LEFT JOIN (
          SELECT c.ve_id, SUM(paq.prix_fcfa) AS total_valeur_paquets
          FROM clients c JOIN paquets paq ON c.paquet_id = paq.id GROUP BY c.ve_id
        ) paq_sum   ON paq_sum.ve_id  = ve.id
        ORDER BY ve.nom
      `);
      return res.json(rows);
    }

    if (["USER", "VE"].includes(req.user.role)) {
      const { rows } = await db.query(
        `SELECT
           ve.id, ve.ve_code, ve.nom, ve.prenom,
           vil.nom_village,
           u.username AS user_account,
           COUNT(DISTINCT c.id)::int           AS nb_inscrits,
           COALESCE(SUM(p.montant), 0)          AS total_paiements,
           CASE WHEN ve.id = $1 THEN 1 ELSE 0 END AS is_active
         FROM ve
         LEFT JOIN villages vil ON ve.village_id = vil.id
         LEFT JOIN users    u   ON ve.user_id    = u.id
         LEFT JOIN clients  c   ON c.ve_id       = ve.id
         LEFT JOIN paiements p  ON c.id          = p.client_id
         GROUP BY ve.id, vil.nom_village, u.username
         ORDER BY ve.nom`,
        [req.user.ve_id]
      );
      return res.json(rows);
    }

    return res.status(403).json({ message: "Accès interdit" });
  } catch (err) {
    console.error("GET /ve:", err.message);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// ==================== VE DETAILS ====================

app.get("/ve/:id", authenticateToken, async (req, res) => {
  const requestedId = parseInt(req.params.id, 10);
  if (isNaN(requestedId)) return res.status(400).json({ message: "ID invalide" });

  if (req.user.role === "VE" && req.user.ve_id !== requestedId)
    return res.status(403).json({ message: "Accès interdit" });

  try {
    const { rows } = await db.query(
      `SELECT v.id, v.ve_code, v.nom, v.prenom, v.village_id, vil.nom_village
       FROM ve v LEFT JOIN villages vil ON vil.id = v.village_id
       WHERE v.id = $1`,
      [requestedId]
    );
    if (!rows.length) return res.status(404).json({ message: "VE introuvable" });
    res.json(rows[0]);
  } catch (err) {
    console.error("GET /ve/:id:", err.message);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// ==================== CLIENTS D'UN VE ====================

app.get("/clients/ve/:ve_id", authenticateToken, async (req, res) => {
  const { ve_id } = req.params;

  // ✅ VE ne peut voir que son propre village (déjà dans ta logique, on la garde)
  const filterVeId    = req.user.role === "ADMIN" ? ve_id       : null;
  const filterVillage = req.user.role === "VE"    ? req.user.village_id : null;

  if (req.user.role !== "ADMIN" && req.user.role !== "VE")
    return res.status(403).json({ message: "Accès interdit" });

  try {
    const whereClause = req.user.role === "ADMIN"
      ? "WHERE c.ve_id = $1"
      : "WHERE c.village_id = $1";
    const param = req.user.role === "ADMIN" ? filterVeId : filterVillage;

    const { rows } = await db.query(
      `SELECT
         c.id, c.client_code, c.nom, c.prenom, c.telephone,
         v.nom_village,
         DATE(c.date_inscription) AS date_inscription,
         COALESCE(SUM(pai.montant), 0) AS total_paiements,
         paq.culture      AS paquet_culture,
         paq.superficie   AS paquet_superficie,
         paq.prix_fcfa    AS paquet_prix,
         paq.composition  AS paquet_composition
       FROM clients c
       LEFT JOIN villages v   ON c.village_id = v.id
       LEFT JOIN paiements pai ON c.id         = pai.client_id
       LEFT JOIN paquets paq   ON c.paquet_id  = paq.id
       ${whereClause}
       GROUP BY c.id, v.nom_village, paq.culture, paq.superficie, paq.prix_fcfa, paq.composition
       ORDER BY c.date_inscription DESC`,
      [param]
    );
    res.json(rows);
  } catch (err) {
    console.error("GET /clients/ve/:ve_id:", err.message);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// ==================== CLIENT DETAILS ====================

app.get("/clients/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  if (isNaN(Number(id))) return res.status(400).json({ message: "ID invalide" });

  try {
    const { rows } = await db.query(
      `SELECT
         c.id, c.client_code, c.nom, c.prenom,
         DATE(c.date_inscription) AS date_inscription,
         c.telephone,
         v.nom_village,
         ve.ve_code, ve.nom AS ve_nom, ve.prenom AS ve_prenom,
         p.culture      AS paquet_culture,
         p.superficie   AS paquet_superficie,
         p.photo_url    AS paquet_photo_url,
         p.prix_fcfa    AS paquet_prix,
         p.composition  AS paquet_composition
       FROM clients c
       LEFT JOIN villages v ON c.village_id = v.id
       LEFT JOIN ve         ON c.ve_id      = ve.id
       LEFT JOIN paquets p  ON c.paquet_id  = p.id
       WHERE c.id = $1`,
      [id]
    );
    if (!rows.length) return res.status(404).json({ message: "Client introuvable" });
    res.json(rows[0]);
  } catch (err) {
    console.error("GET /clients/:id:", err.message);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// ==================== AJOUTER UN CLIENT ====================

app.post("/clients", authenticateToken, async (req, res) => {
  return withIdempotency(req, res, "POST:/clients", async () => {
    const pgClient = await db.connect();
    try {
      const { ve_id, nom, prenom, telephone, montant, numero_recu, paquet_id } = req.body;
      if (!ve_id || !nom || !prenom || !telephone)
        return res.status(400).json({ message: "Champs manquants" });

      // Vérification VE
      if (req.user.role !== "ADMIN") {
        const { rows } = await pgClient.query("SELECT id FROM ve WHERE user_id = $1", [req.user.id]);
        if (!rows.length || rows[0].id !== Number(ve_id))
          return res.status(403).json({ message: "Accès interdit" });
      }

      const veRes = await pgClient.query("SELECT village_id FROM ve WHERE id = $1", [ve_id]);
      if (!veRes.rows.length) return res.status(400).json({ message: "VE introuvable" });
      const village_id = veRes.rows[0].village_id;

      await pgClient.query("BEGIN");

      // Doublon client
      const dup = await pgClient.query(
        "SELECT id FROM clients WHERE nom=$1 AND prenom=$2 AND telephone=$3 AND village_id=$4 LIMIT 1",
        [nom, prenom, telephone, village_id]
      );
      if (dup.rows.length > 0) {
        await pgClient.query("ROLLBACK");
        return res.status(409).json({ message: "Ce client existe déjà dans ce village." });
      }

      // Vérif reçu
      if (montant && Number(montant) > 0) {
        if (!numero_recu?.trim())
          return (await pgClient.query("ROLLBACK"), res.status(400).json({ message: "Le numéro de reçu est obligatoire." }));

        const cnt = await checkRecuLimit(pgClient, numero_recu, montant);
        if (cnt >= 2)
          return (await pgClient.query("ROLLBACK"), res.status(400).json({ message: "Ce reçu a déjà été utilisé 2 fois (limite atteinte)." }));
      }

      // Insert client
      const client_code = `CL-${ve_id}-${Date.now()}`;
      const { rows: inserted } = await pgClient.query(
        `INSERT INTO clients (client_code, nom, prenom, ve_id, village_id, date_inscription, telephone, paquet_id)
         VALUES ($1,$2,$3,$4,$5,NOW(),$6,$7) RETURNING id`,
        [client_code, nom, prenom, ve_id, village_id, telephone, paquet_id ?? null]
      );
      const client_id = inserted[0].id;

      // Paiement initial
      if (montant && Number(montant) > 0) {
        await pgClient.query(
          `INSERT INTO paiements (client_id, montant, date_paiement, user_id, numero_recu) VALUES ($1,$2,NOW(),$3,$4)`,
          [client_id, montant, req.user.id, numero_recu.trim()]
        );
      }

      await pgClient.query("COMMIT");
      return res.json({ message: "Client créé avec succès", client_id });
    } catch (err) {
      await pgClient.query("ROLLBACK").catch(() => {});
      console.error("POST /clients:", err.message);
      return res.status(500).json({ message: "Erreur serveur" });
    } finally {
      pgClient.release();
    }
  });
});

// ==================== HISTORIQUE PAIEMENTS D'UN CLIENT ====================

app.get("/paiements/client/:client_id", authenticateToken, async (req, res) => {
  const { client_id } = req.params;
  if (isNaN(Number(client_id))) return res.status(400).json({ message: "ID invalide" });

  try {
    if (req.user.role !== "ADMIN") {
      const { rows } = await db.query(
        `SELECT c.id FROM clients c
         JOIN ve ON c.ve_id = ve.id
         WHERE c.id = $1 AND ve.user_id = $2`,
        [client_id, req.user.id]
      );
      if (!rows.length) return res.status(403).json({ message: "Accès interdit" });
    }

    const { rows } = await db.query(
      `SELECT p.id AS paiement_id, p.numero_recu, p.montant, p.date_paiement,
              u.username AS payeur_username
       FROM paiements p
       LEFT JOIN users u ON p.user_id = u.id
       WHERE p.client_id = $1
       ORDER BY p.date_paiement DESC`,
      [client_id]
    );
    res.json(rows);
  } catch (err) {
    console.error("GET /paiements/client/:id:", err.message);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// ==================== AJOUTER UN PAIEMENT ====================

app.post("/paiements", authenticateToken, paiementLimiter, async (req, res) => {
  return withIdempotency(req, res, "POST:/paiements", async () => {
    const { client_id, montant, password, numero_recu } = req.body;

    if (!numero_recu?.trim())
      return res.status(400).json({ message: "Le numéro de reçu est obligatoire." });
    if (!montant || isNaN(Number(montant)) || Number(montant) <= 0)
      return res.status(400).json({ message: "Montant invalide." });

    try {
      const { rows } = await db.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
      if (!rows.length) return res.status(400).json({ message: "Utilisateur introuvable" });

      const match = await bcrypt.compare(password, rows[0].password_hash);
      if (!match) return res.status(400).json({ message: "Mot de passe incorrect" });

      if (req.user.role === "VE") {
        const { rows: check } = await db.query(
          `SELECT c.id FROM clients c JOIN ve ON c.ve_id = ve.id
           WHERE c.id = $1 AND ve.user_id = $2`,
          [client_id, req.user.id]
        );
        if (!check.length) return res.status(403).json({ message: "Accès interdit" });
      }

      const cnt = await checkRecuLimit(db, numero_recu, montant);
      if (cnt >= 2)
        return res.status(400).json({ message: "Ce reçu a déjà été utilisé 2 fois (limite atteinte)." });

      await db.query(
        `INSERT INTO paiements (client_id, montant, date_paiement, user_id, numero_recu)
         VALUES ($1,$2,NOW(),$3,$4)`,
        [client_id, montant, req.user.id, numero_recu.trim()]
      );

      return res.json({ message: "Paiement enregistré", numero_recu: numero_recu.trim() });
    } catch (err) {
      console.error("POST /paiements:", err.message);
      return res.status(500).json({ message: "Erreur serveur" });
    }
  });
});

// ==================== PAQUETS (avec cache) ====================

app.get("/paquets", authenticateToken, async (req, res) => {
  const cached = paquetCache.get("all");
  if (cached) return res.json(cached);

  try {
    const { rows } = await db.query("SELECT * FROM paquets ORDER BY culture, superficie");
    paquetCache.set("all", rows);
    res.json(rows);
  } catch (err) {
    console.error("GET /paquets:", err.message);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// ================================================
// 🚀 START
// ================================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => console.log(`🚀 Serveur lancé sur le port ${PORT}`));