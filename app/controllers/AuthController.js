const db = require("../config/db");

module.exports = {
  // ----------------------------------------------------------
  // POST /api/auth/login
  // ----------------------------------------------------------
  login: (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email et mot de passe requis" });
    }

    //requête SQL avec parametre passés en tableau
    const query = "SELECT * FROM users WHERE email = ? AND password = ?";

    db.query(query, [email, password], (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message, query: query });
      }

      if (results.length === 0) {
        return res
          .status(401)
          .json({ error: "Email ou mot de passe incorrect" });
      }

      // Connexion réussie
      res.json({ message: "Connexion réussie" });
    });
  },

  // ----------------------------------------------------------
  // POST /api/auth/register
  // ----------------------------------------------------------
  register: (req, res) => {
    const { username, address, email, password } = req.body;
    const query =
      "INSERT INTO users (username, address, email, password) VALUES (?, ?, ?, ?)";

    db.query(query, [username, address, email, password], (err) => {
      if (err) return res.status(500).send(err.message);

      res.json({ message: "Utilisateur créé !" });
    });
  },
};
