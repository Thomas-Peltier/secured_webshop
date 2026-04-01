const db = require("../config/db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const saltRounds = 10;
const peper = "GZG4g78FUFü!EU%UIHIFU";
const jwtSecret = "123456789abc";

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
      const pwdPeper = password + peper;
      const match = await bcrypt.compare(pwdPeper, user.password);

      if (match) {
        const token = jwt.sign({ id: user.id, email: user.email }, jwtSecret, {
          expiresIn: "1h",
        });
        res.json({ message: "Connexion réussie", token: token });
      } else {
        res.status(401).json({ error: "Email ou mot de passe incorrect" });
      }
    });
  },

  // ----------------------------------------------------------
  // POST /api/auth/register
  // ----------------------------------------------------------
  register: async (req, res) => {
    const { username, address, email, password } = req.body;

    //on hash le mot de passe + le peper avant de le insert
    const pwdPeper = password + peper;
    const hashedPassword = await bcrypt.hash(pwdPeper, saltRounds);

    const query =
      "INSERT INTO users (username, address, email, password) VALUES (?, ?, ?, ?)";
    db.query(query, [username, address, email, hashedPassword], (err) => {
      if (err) return res.status(500).send(err.message);
      res.json({ message: "Utilisateur créé !" });
    });
  },
};
