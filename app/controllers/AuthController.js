const db = require("../config/db");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const peper = "GZG4g78FUFü!EU%UIHIFU";

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
      const pwdWithPeper = password + peper;
      const match = await bcrypt.compare(pwdWithPeper, user.password);

      if (match) {
        res.json({ message: "Connexion réussie" });
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
    const pwdWithPeper = password + peper;
    const hashedPassword = await bcrypt.hash(pwdWithPeper, saltRounds);

    const query =
      "INSERT INTO users (username, address, email, password) VALUES (?, ?, ?, ?)";
    db.query(query, [username, address, email, hashedPassword], (err) => {
      if (err) return res.status(500).send(err.message);
      res.json({ message: "Utilisateur créé !" });
    });
  },
};
