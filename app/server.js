const path = require("path");
const fs = require("fs");
const https = require("https");

require("dotenv").config({ path: path.resolve(__dirname, "..", ".env") });

const express = require("express");
const rateLimit = require("express-rate-limit");

const app = express();

const loginLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 5,
  message: { error: "Trop de tentatives. Réessayez dans une minute." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Middleware pour parser le corps des requêtes
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Fichiers statiques (CSS, images, uploads...)
app.use(express.static(path.join(__dirname, "public")));
// ---------------------------------------------------------------
// Routes API (retournent du JSON)
// ---------------------------------------------------------------
const authRoute = require("./routes/Auth");
const profileRoute = require("./routes/Profile");
const adminRoute = require("./routes/Admin");

app.use("/api/auth", loginLimiter, authRoute);
app.use("/api/profile", profileRoute);
app.use("/api/admin", adminRoute);
// ---------------------------------------------------------------
// Routes pages (retournent du HTML)
// ---------------------------------------------------------------
const homeRoute = require("./routes/Home");
const userRoute = require("./routes/User");

app.use("/", homeRoute);
app.use("/user", userRoute);

app.get("/login", (_req, res) =>
  res.sendFile(path.join(__dirname, "views", "login.html")),
);
app.get("/register", (_req, res) =>
  res.sendFile(path.join(__dirname, "views", "register.html")),
);
app.get("/profile", (_req, res) =>
  res.sendFile(path.join(__dirname, "views", "profile.html")),
);
app.get("/admin", (_req, res) =>
  res.sendFile(path.join(__dirname, "views", "admin.html")),
);

app.get("/test", (_req, res) => res.send("db admin: root, pwd : root"));

const sslOptions = {
  key: fs.readFileSync(path.join(__dirname, "localhost+1-key.pem")),
  cert: fs.readFileSync(path.join(__dirname, "localhost+1.pem")),
};

https.createServer(sslOptions, app).listen(8080, () => {
  console.log("Serveur démarré sur https://localhost:8080");
});
