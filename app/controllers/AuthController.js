const db = require("../config/db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const saltRounds = 10;

const sendServerError = (res, context, err) => {
  console.error(context, err);
  return res.status(500).json({ error: "Erreur serveur" });
};

module.exports = {
  login: (req, res) => {
    const { email, password } = req.body;

    const query = "SELECT * FROM users WHERE email = ?";
    db.query(query, [email], async (err, results) => {
      if (err) return sendServerError(res, "Auth login db error:", err);

      if (results.length === 0) {
        return res
          .status(401)
          .json({ error: "Email ou mot de passe incorrect" });
      }

      const user = results[0];
      const pwdPeper = password + process.env.PEPER;

      try {
        //on compare le mdp saisi avec le hash (mdp + sel + poivre) en db
        const match = await bcrypt.compare(pwdPeper, user.password);

        if (!match) {
          return res
            .status(401)
            .json({ error: "Email ou mot de passe incorrect" });
        }

        const payload = { id: user.id, email: user.email, role: user.role };
        const token = jwt.sign(payload, process.env.JWT_SECRET, {
          expiresIn: "10s",
        });
        const refreshToken = jwt.sign(
          payload,
          process.env.REFRESH_TOKEN_SECRET,
          {
            expiresIn: "7d",
          },
        );

        const updateQuery = "UPDATE users SET refresh_token = ? WHERE id = ?";
        db.query(updateQuery, [refreshToken, user.id], (updErr) => {
          if (updErr)
            return sendServerError(
              res,
              "Auth login refresh token update error:",
              updErr,
            );

          res.json({
            message: "Connexion réussie",
            token,
            refreshToken,
          });
        });
      } catch (error) {
        return sendServerError(res, "Auth login processing error:", error);
      }
    });
  },

  // ----------------------------------------------------------
  // POST /api/auth/register
  // ----------------------------------------------------------
  refresh: (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401).json({ error: "Refresh token requis" });
    }

    const query = "SELECT * FROM users WHERE refresh_token = ?";
    db.query(query, [refreshToken], (err, results) => {
      if (err) return sendServerError(res, "Auth refresh database error:", err);

      if (results.length === 0) {
        return res.status(403).json({ error: "Token invalide" });
      }

      const user = results[0];
      jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (verifErr) => {
        if (verifErr) {
          return res.status(403).json({ error: "Token expiré" });
        }

        const newToken = jwt.sign(
          { id: user.id, email: user.email, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: "10m" },
        );

        res.json({ token: newToken });
      });
    });
  },

  register: async (req, res) => {
    const { username, address, email, password } = req.body;

    try {
      const pwdPeper = password + process.env.PEPER;
      const hashedPassword = await bcrypt.hash(pwdPeper, saltRounds);

      const query =
        "INSERT INTO users (username, address, email, password) VALUES (?, ?, ?, ?)";
      db.query(query, [username, address, email, hashedPassword], (err) => {
        if (err)
          return sendServerError(res, "Auth register database error:", err);
        res.json({ message: "Utilisateur créé !" });
      });
    } catch (error) {
      return sendServerError(res, "Auth register processing error:", error);
    }
  },
};
