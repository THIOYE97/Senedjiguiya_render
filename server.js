import express from "express";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import { parse } from "pg-connection-string"; // <== IMPORTANT

// === Gestion globale des erreurs non gérées ===
process.on("unhandledRejection", (err) => {
  console.error("🚨 Promise non gérée:", err);
});

process.on("uncaughtException", (err) => {
  console.error("💥 Erreur fatale:", err);
});

dotenv.config();
const { Pool } = pkg;

const app = express();
app.use(express.json());
app.use(cors({ origin: "*" }));

// ================================================
// 🚨 FIX RENDER : empêcher PGHOST/PGPORT de casser Supabase
// ================================================

const parsed = parse(process.env.DATABASE_URL);

const db = new Pool({
  host: parsed.host,
  port: parsed.port,
  user: parsed.user,
  password: parsed.password,
  database: parsed.database,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  keepAlive: true,
});

// ================================================
// 🔄 TEST + RECONNEXION AUTO
// ================================================

async function testDBConnection() {
  try {
    const client = await db.connect();
    console.log("✅ Connexion PostgreSQL active");
    client.release();
  } catch (err) {
    console.error("⚠️ Erreur connexion DB:", err.code || err.message);
    console.log("🔄 Nouvelle tentative de connexion dans 5 secondes...");
    setTimeout(testDBConnection, 5000);
  }
}

testDBConnection();

// Gestion d'erreurs asynchrones
db.on("error", (err) => {
  console.error("🚨 Erreur inattendue du pool PostgreSQL:", err.message);
  console.log("🔁 Tentative de reconnexion automatique...");
  setTimeout(testDBConnection, 5000);
});

// ================================================
// 💓 Ping DB (garde la connexion vivante)
// ================================================
setInterval(async () => {
  try {
    await db.query("SELECT 1");
    console.log("💓 Ping DB OK");
  } catch (err) {
    console.error("💀 Ping DB échoué:", err.message);
  }
}, 4 * 60 * 1000);


export { db };


// === AUTHENTIFICATION ===
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token manquant" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Token invalide" });
    req.user = user;
    next();
  });
}

// === PERMISSIONS ===
async function hasPermission(role, permissionName) {
  const result = await db.query(
    `SELECT p.name 
     FROM roles r
     JOIN roles_permissions rp ON r.id = rp.role_id
     JOIN permissions p ON p.id = rp.permission_id
     WHERE r.name = $1 AND p.name = $2`,
    [role, permissionName]
  );
  return result.rows.length > 0;
}

function requirePermission(permissionName) {
  return async (req, res, next) => {
    const allowed = await hasPermission(req.user.role, permissionName);
    if (!allowed) return res.status(403).json({ message: "Accès interdit" });
    next();
  };
}

// === REGISTER ===
app.post("/register", authenticateToken, requirePermission("manage_users"), async (req, res) => {
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
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// === LOGIN ===
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0)
      return res.status(400).json({ message: "Utilisateur non trouvé" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ message: "Mot de passe incorrect" });

    // Chercher ve_id et village_id
    let ve_id = null;
    let village_id = null;

    if (user.role === "VE") {
      const veRes = await db.query(
        "SELECT id, village_id FROM ve WHERE user_id = $1",
        [user.id]
      );
      if (veRes.rows.length > 0) {
        ve_id = veRes.rows[0].id;
        village_id = veRes.rows[0].village_id;
      }
    }

    const token = jwt.sign(
      { id: user.id, role: user.role, ve_id, village_id },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role, ve_id, village_id },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// === ME ===
app.get("/me", authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT id, username, role FROM users WHERE id = $1",
      [req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ message: "Utilisateur introuvable" });
    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// === VE ===
app.get("/ve", authenticateToken, async (req, res) => {
  try {
    let result;

    if (req.user.role === "ADMIN") {
      result = await db.query(`
       SELECT 
  ve.id,
  ve.ve_code,
  ve.nom,
  ve.prenom,
  vil.nom_village,
  u.username AS user_account,
  COALESCE(c_count.nb_inscrits, 0) AS nb_inscrits,
  COALESCE(p_sum.total_paiements, 0) AS total_paiements,
  COALESCE(paq_sum.total_valeur_paquets, 0) AS total_valeur_paquets
FROM ve
LEFT JOIN villages vil ON ve.village_id = vil.id
LEFT JOIN users u ON ve.user_id = u.id

-- 🔹 Sous-requête pour compter les clients
LEFT JOIN (
  SELECT ve_id, COUNT(DISTINCT id) AS nb_inscrits
  FROM clients
  GROUP BY ve_id
) AS c_count ON c_count.ve_id = ve.id

-- 🔹 Sous-requête pour la somme des paiements
LEFT JOIN (
  SELECT c.ve_id, SUM(p.montant) AS total_paiements
  FROM paiements p
  JOIN clients c ON p.client_id = c.id
  GROUP BY c.ve_id
) AS p_sum ON p_sum.ve_id = ve.id

-- 🔹 Sous-requête pour la valeur totale des paquets
LEFT JOIN (
  SELECT ve_id, SUM(paq.prix_fcfa) AS total_valeur_paquets
  FROM clients c
  JOIN paquets paq ON c.paquet_id = paq.id
  GROUP BY ve_id
) AS paq_sum ON paq_sum.ve_id = ve.id

ORDER BY ve.nom;

      `);
    } else if (["USER", "VE"].includes(req.user.role)) {
      result = await db.query(
        `
        SELECT ve.id, ve.ve_code, ve.nom, ve.prenom,
               vil.nom_village,
               u.username AS user_account,
               COUNT(DISTINCT c.id) AS nb_inscrits,
               COALESCE(SUM(p.montant), 0) AS total_paiements,
               CASE WHEN ve.id = $1 THEN 1 ELSE 0 END AS is_active
        FROM ve
        LEFT JOIN villages vil ON ve.village_id = vil.id
        LEFT JOIN users u ON ve.user_id = u.id
        LEFT JOIN clients c ON c.ve_id = ve.id
        LEFT JOIN paiements p ON c.id = p.client_id
        GROUP BY ve.id, vil.nom_village, u.username
      `,
        [req.user.ve_id]
      );
    } else {
      return res.status(403).json({ message: "Accès interdit" });
    }

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// === VE DETAILS ===
app.get("/ve/:id", authenticateToken, async (req, res) => {
  const requestedId = parseInt(req.params.id);
  const user = req.user;
  try {
    const result = await db.query(
      `SELECT v.id, v.ve_code, v.nom, v.prenom, v.village_id,
              vil.nom_village
       FROM ve v
       LEFT JOIN villages vil ON vil.id = v.village_id
       WHERE v.id = $1`,
      [requestedId]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ message: "VE introuvable" });

    if (user.role === "VE" && user.ve_id !== requestedId)
      return res.status(403).send("Accès interdit");

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Erreur serveur" });
  }
});
// === AJOUTER UN CLIENT ===
app.post("/clients", authenticateToken, async (req, res) => {
  try {
    const { ve_id, nom, prenom, telephone, montant, numero_recu, paquet_id } = req.body;

    // Vérifications des champs obligatoires
    if (!ve_id || !nom || !prenom || !telephone)
      return res.status(400).json({ message: "Champs manquants" });

    // Vérification VE (si l'utilisateur n'est pas admin)
    if (req.user.role !== "ADMIN") {
      const checkVe = await db.query("SELECT id FROM ve WHERE user_id = $1", [req.user.id]);
      if (checkVe.rows.length === 0 || checkVe.rows[0].id !== Number(ve_id))
        return res.status(403).json({ message: "Accès interdit" });
    }

    // Récupération du village du VE
    const veRes = await db.query("SELECT village_id FROM ve WHERE id = $1", [ve_id]);
    if (veRes.rows.length === 0)
      return res.status(400).json({ message: "VE introuvable" });

    const village_id = veRes.rows[0].village_id;
    const client_code = `CL-${ve_id}-${Date.now()}`;

    // ✅ Création du client (avec paquet_id inclus)
    const insert = await db.query(
      `INSERT INTO clients (client_code, nom, prenom, ve_id, village_id, date_inscription, telephone, paquet_id)
       VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7)
       RETURNING id`,
      [client_code, nom, prenom, ve_id, village_id, telephone, paquet_id || null]
    );

    const client_id = insert.rows[0].id;

    // 🧾 Si un montant est saisi, le numéro de reçu devient obligatoire
    if (montant && Number(montant) > 0) {
      if (!numero_recu || numero_recu.trim() === "") {
        return res.status(400).json({
          message: "Le numéro de reçu est obligatoire pour un paiement initial."
        });
      }

      // Vérifie unicité du numéro de reçu + montant
      const recuCheck = await db.query(
        "SELECT id FROM paiements WHERE numero_recu = $1 AND montant = $2",
        [numero_recu.trim(), montant]
      );
      if (recuCheck.rows.length > 0) {
        return res.status(400).json({
          message: "Ce numéro de reçu existe déjà pour ce montant."
        });
      }

      // 💰 Enregistrement du paiement initial
      await db.query(
        `INSERT INTO paiements (client_id, montant, date_paiement, user_id, numero_recu)
         VALUES ($1, $2, NOW(), $3, $4)`,
        [client_id, montant, req.user.id, numero_recu.trim()]
      );
    }

    res.json({ message: "✅ Client créé avec succès", client_id });
  } catch (err) {
    console.error("Erreur POST /clients:", err);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// === CLIENTS D’UN VE OU D’UN VILLAGE ===
app.get("/clients/ve/:ve_id", authenticateToken, async (req, res) => {
  const { ve_id } = req.params;
  try {
    let result;

    // ADMIN → voit tous les clients du VE
    if (req.user.role === "ADMIN") {
      result = await db.query(
        `
        SELECT 
          c.id, c.client_code, c.nom, c.prenom, c.telephone,
          v.nom_village, DATE(c.date_inscription) AS date_inscription,
          COALESCE(SUM(pai.montant), 0) AS total_paiements,
          paq.culture AS paquet_culture,
          paq.superficie AS paquet_superficie,
          paq.prix_fcfa AS paquet_prix,
          paq.composition AS paquet_composition
        FROM clients c
        LEFT JOIN villages v ON c.village_id = v.id
        LEFT JOIN paiements pai ON c.id = pai.client_id
        LEFT JOIN paquets paq ON c.paquet_id = paq.id
        WHERE c.ve_id = $1
        GROUP BY 
          c.id, v.nom_village, paq.culture, paq.superficie, paq.prix_fcfa, paq.composition
        ORDER BY c.date_inscription DESC
        `,
        [ve_id]
      );

    // VE → ne voit que ses clients de son propre village
    } else if (req.user.role === "VE") {
      result = await db.query(
        `
        SELECT 
          c.id, c.client_code, c.nom, c.prenom, c.telephone,
          v.nom_village, DATE(c.date_inscription) AS date_inscription,
          COALESCE(SUM(pai.montant), 0) AS total_paiements,
          paq.culture AS paquet_culture,
          paq.superficie AS paquet_superficie,
          paq.prix_fcfa AS paquet_prix,
          paq.composition AS paquet_composition
        FROM clients c
        LEFT JOIN villages v ON c.village_id = v.id
        LEFT JOIN paiements pai ON c.id = pai.client_id
        LEFT JOIN paquets paq ON c.paquet_id = paq.id
        WHERE c.village_id = $1
        GROUP BY 
          c.id, v.nom_village, paq.culture, paq.superficie, paq.prix_fcfa, paq.composition
        ORDER BY c.date_inscription DESC
        `,
        [req.user.village_id]
      );
    } else {
      return res.status(403).json({ message: "Accès interdit" });
    }

    res.json(result.rows);
  } catch (error) {
    console.error("Erreur SQL:", error);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// === HISTORIQUE DES PAIEMENTS D’UN CLIENT ===
app.get("/paiements/client/:client_id", authenticateToken, async (req, res) => {
  const { client_id } = req.params;
  try {
    // Vérification des droits
    if (req.user.role !== "ADMIN") {
      const check = await db.query(
        `SELECT c.id
         FROM clients c
         JOIN ve ON c.ve_id = ve.id
         WHERE c.id = $1 AND ve.user_id = $2`,
        [client_id, req.user.id]
      );
      if (check.rows.length === 0)
        return res.status(403).json({ message: "Accès interdit" });
    }

    const result = await db.query(
      `
      SELECT 
        p.id AS paiement_id,
        p.numero_recu,
        p.montant,
        p.date_paiement,
        u.username AS payeur_username
      FROM paiements p
      JOIN clients c ON p.client_id = c.id
      LEFT JOIN users u ON p.user_id = u.id
      WHERE p.client_id = $1
      ORDER BY p.date_paiement DESC
      `,
      [client_id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur serveur" });
  }
});
// === CLIENT DETAILS ===
app.get("/clients/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await db.query(
      `
      SELECT 
        c.id, c.client_code, c.nom, c.prenom,
        DATE(c.date_inscription) AS date_inscription,
        c.telephone, v.nom_village, 
        ve.ve_code, ve.nom AS ve_nom, ve.prenom AS ve_prenom,
        p.culture AS paquet_culture,
        p.superficie AS paquet_superficie,
        p.photo_url AS paquet_photo_url,
        p.prix_fcfa AS paquet_prix,
        p.composition AS paquet_composition
      FROM clients c
      LEFT JOIN villages v ON c.village_id = v.id
      LEFT JOIN ve ON c.ve_id = ve.id
      LEFT JOIN paquets p ON c.paquet_id = p.id
      WHERE c.id = $1
      `,
      [id]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ message: "Client introuvable" });

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// === AJOUTER UN PAIEMENT ===
app.post("/paiements", authenticateToken, async (req, res) => {
  const { client_id, montant, password, numero_recu } = req.body;

  try {
    if (!numero_recu || numero_recu.trim() === "")
      return res.status(400).json({ message: "Le numéro de reçu est obligatoire." });

    const userRes = await db.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    if (userRes.rows.length === 0)
      return res.status(400).json({ message: "Utilisateur introuvable" });

    const user = userRes.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ message: "Mot de passe incorrect" });

    // Vérification VE
    if (req.user.role === "VE") {
      const check = await db.query(
        `SELECT c.id
         FROM clients c
         JOIN ve ON c.ve_id = ve.id
         WHERE c.id = $1 AND ve.user_id = $2`,
        [client_id, req.user.id]
      );
      if (check.rows.length === 0)
        return res.status(403).json({ message: "Accès interdit" });
    }

   // Vérifier si le reçu existe déjà avec le même montant
const recuCheck = await db.query(
  "SELECT id FROM paiements WHERE numero_recu = $1 AND montant = $2",
  [numero_recu, montant]
);

if (recuCheck.rows.length > 0) {
  return res.status(400).json({
    message: "Ce numéro de reçu existe déjà pour ce montant.",
  });
}

    // Enregistrer le paiement
    await db.query(
      `INSERT INTO paiements (client_id, montant, date_paiement, user_id, numero_recu)
       VALUES ($1, $2, NOW(), $3, $4)`,
      [client_id, montant, req.user.id, numero_recu]
    );

    res.json({ message: "Paiement enregistré avec succès", numero_recu });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur serveur" });
  }
});
// === HISTORIQUE DES PAIEMENTS D’UN CLIENT
app.get("/paiements/client/:client_id", authenticateToken, async (req, res) => {
  const { client_id } = req.params;
  try {
    // Vérification des droits
    if (req.user.role !== "ADMIN") {
      const check = await db.query(
        `SELECT c.id
         FROM clients c
         JOIN ve ON c.ve_id = ve.id
         WHERE c.id = $1 AND ve.user_id = $2`,
        [client_id, req.user.id]
      );
      if (check.rows.length === 0)
        return res.status(403).json({ message: "Accès interdit" });
    }

    const result = await db.query(
      `
      SELECT 
        p.id AS paiement_id,
        p.numero_recu,
        p.montant,
        p.date_paiement,
        u.username AS payeur_username
      FROM paiements p
      JOIN clients c ON p.client_id = c.id
      LEFT JOIN users u ON p.user_id = u.id
      WHERE p.client_id = $1
      ORDER BY p.date_paiement DESC
      `,
      [client_id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// === GET TOUS LES PAQUETS ===
app.get("/paquets", authenticateToken, async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM paquets ORDER BY culture, superficie");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// === ROUTE DE TEST / ===
app.get("/", (req, res) => {
  res.send("✅ API Senedjiguiya en ligne !");
});
// === START ===
const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => console.log(`🚀 Serveur lancé sur le port ${PORT}`));
