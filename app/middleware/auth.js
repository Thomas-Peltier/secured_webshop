// =============================================================
// Middleware d'authentification
// =============================================================

const jwt = require("jsonwebtoken");

module.exports = {
  verifyToken: (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(403).json({ error: "Aucun token trouvé" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) return res.status(401).json({ error: "Token invalide" });
      req.user = decoded;
      next();
    });
  },

  isAdmin: (req, res, next) => {
    console.log("DEBUG ROLE :", req.user.role);

    if (req.user && String(req.user.role).toLowerCase() === "admin") {
      next();
    } else {
      res.status(403).json({ error: "Accès refusé : tu n'es pas admin" });
    }
  },
};
