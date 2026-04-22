const express = require("express");
const router = express.Router();
const controller = require("../controllers/AdminController");

const { verifyToken, isAdmin } = require("../middleware/auth");

router.get("/users", verifyToken, isAdmin, controller.getUsers);

module.exports = router;
