const express = require("express");
const router = express.Router();
const controller = require("../controllers/AuthController");

router.post("/login", controller.login);
router.post("/register", controller.register);

module.exports = router;

router.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

  if (!passwordRegex.test(password)) {
    return res.status(400).json({
      error:
        "Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial.",
    });
  }
});
