const express = require("express");
const morgan = require("morgan");
const http = require("http");
const path = require("path");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite-async");
const bodyParser = require("body-parser");
const passport = require("passport");
const passportJWT = require("passport-jwt");
const jwt = require("jsonwebtoken");

const port = 4000;
const app = express();
const server = http.createServer(app);

let database = null;
const initDatabasePromise = new Promise((resolve, reject) => {
  const databaseFile = path.join(__dirname, "users.db");
  sqlite3
    .open(databaseFile)
    .then((result) => {
      database = result;
      console.log(` * Sqlite3 database [${databaseFile}] connected`);
      resolve();
    })
    .catch((error) => {
      console.log(` * Sqlite3 database [${databaseFile}] error`);
      console.error(error);
    });
});

if (!module.parent) {
  app.use(morgan("dev"));
}

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

console.log(" * Set up authentication");
const jwtOptions = {
  jwtFromRequest: passportJWT.ExtractJwt.fromAuthHeaderAsBearerToken(),
  expiresIn: "7 days",
  secretOrKey: "7bba01ae-e504-4330-a4e2-d26ed003e194",
};

const strategy = new passportJWT.Strategy(
  jwtOptions,
  async (jwt_payload, done) => {
    try {
      await initDatabasePromise;

      const result = await database.all(
        "SELECT UserId, Email FROM User WHERE UserId=? LIMIT 1",
        [jwt_payload.userId]
      );
      if (result.length === 1) {
        done(null, { userId: result[0].UserId, loginId: result[0].Email });
        return;
      }
    } catch (error) {
      console.log(error);
    }

    done(null, false);
  }
);

passport.use(strategy);
app.use(passport.initialize());

const useAuth = passport.authenticate("jwt", { session: false });

app.post("/login", async (req, res) => {
  try {
    await initDatabasePromise;

    const email = (req.body.email || "").trim();
    const password = req.body.password;

    const result = await database.all(
      "SELECT UserId, Password FROM User WHERE Email=? LIMIT 1",
      [email]
    );
    if (result.length !== 1) {
      res.status(400).json({ error: "User does not exist" });
      return;
    }

    if (!bcrypt.compareSync(password, result[0].Password)) {
      res.status(400).json({ error: "Password is wrong" });
      return;
    }

    const payload = { userId: result[0].UserId, email: result[0].Email };
    const accessToken = jwt.sign(payload, jwtOptions.secretOrKey, {
      expiresIn: jwtOptions.expiresIn,
    });
    res.json({ accessToken });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message + "\n\n" + error.stack });
  }
});

app.post("/create", async (req, res) => {
  try {
    await initDatabasePromise;

    const email = (req.body.email || "").trim();
    const password = req.body.password;

    let result = await database.all(
      "SELECT 1 FROM User WHERE Email=? LIMIT 1",
      [email]
    );
    if (result.length === 1) {
      res.status(400).json({ error: "User already exist" });
      return;
    }

    result = await database.all(
      "INSERT INTO User(Email, Password) VALUES(?, ?)",
      [email, bcrypt.hashSync(password, 10)]
    );

    result = await database.all(
      "SELECT UserId, Email FROM User WHERE Email=? LIMIT 1",
      [email]
    );

    const payload = { userId: result[0].UserId, email: result[0].Email };
    const accessToken = jwt.sign(payload, jwtOptions.secretOrKey, {
      expiresIn: jwtOptions.expiresIn,
    });
    res.status(201).json({ accessToken });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message + "\n\n" + error.stack });
  }
});

app.post("/changePassword", useAuth, async (req, res) => {
  try {
    await initDatabasePromise;

    const password = req.body.password;
    const userId = req.user.userId;

    await database.all("UPDATE User SET Password=? WHERE UserId=?", [
      password,
      userId,
    ]);

    res.status(200).send();
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message + "\n\n" + error.stack });
  }
});

/* istanbul ignore next */
if (!module.parent) {
  server.listen(port);
  console.log(` * Service started on Port ${port}`);
}
