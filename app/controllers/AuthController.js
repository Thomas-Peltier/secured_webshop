const db = require("../config/db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const saltRounds = 10;

module.exports = {
  login: (req, res) => {
    const { email, password } = req.body;

    //on cherche l'utilisateur par son email
    const query = "SELECT * FROM users WHERE email = ?";
    db.query(query, [email], async (err, results) => {
      if (err) return res.status(500).json({ error: err.message });

      if (results.length === 0) {
        return res
          .status(401)
          .json({ error: "Email ou mot de passe incorrect" });
      }

      const user = results[0];

      //on compare le mdp saisi avec le hash (mdp + sel + poivre) en db
      const pwdPeper = password + process.env.PEPER;
      const match = await bcrypt.compare(pwdPeper, user.password);

      if (match) {
        const payload = { id: user.id, email: user.email, role: user.role };

        const token = jwt.sign(payload, process.env.JWT_SECRET, {
          expiresIn: "10s",
        });

        const refreshToken = jwt.sign(
          payload,
          process.env.REFRESH_TOKEN_SECRET,
          { expiresIn: "7d" },
        );

        const updateQuery = "UPDATE users SET refresh_token = ? WHERE id = ?";
        db.query(updateQuery, [refreshToken, user.id], (updErr) => {
          if (updErr) return res.status(500).json({ error: updErr.message });

          res.json({
            message: "Connexion réussie",
            token: token,
            refreshToken: refreshToken,
          });
        });
      } else {
        res.status(401).json({ error: "Email ou mot de passe incorrect" });
      }
    });
  },

  // ----------------------------------------------------------
  // POST /api/auth/register
  // ----------------------------------------------------------
  refresh: (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(401).json({ error: "Refresh token requis" });

    const query = "SELECT * FROM users WHERE refresh_token = ?";
    db.query(query, [refreshToken], (err, results) => {
      if (err || results.length === 0)
        return res.status(403).json({ error: "Token invalide" });

      const user = results[0];

      jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        (verifErr, decoded) => {
          if (verifErr)
            return res.status(403).json({ error: "Token expiré ou corrompu" });

          const newToken = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "10m" },
          );

          res.json({ token: newToken });
        },
      );
    });
  },

  register: async (req, res) => {
    const { username, address, email, password } = req.body;

    //on hash le mot de passe + le peper avant de le insert
    const pwdPeper = password + process.env.PEPER;
    const hashedPassword = await bcrypt.hash(pwdPeper, saltRounds);

    const query =
      "INSERT INTO users (username, address, email, password) VALUES (?, ?, ?, ?)";
    db.query(query, [username, address, email, hashedPassword], (err) => {
      if (err) return res.status(500).send(err.message);
      res.json({ message: "Utilisateur créé !" });
    });
  },
};
