import express from "express";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { PORT, SECRET_JWT_KEY } from "./config.js";
import { userRepository } from "./user-repository.js";

const app = express();

// Visualizacion de plantillas
app.set("view engine", "ejs");

// express middleware
app.use(express.json());
// cookie parser middleware
app.use(cookieParser());

// session middleware
app.use((req, res, next) => {
  const token = req.cookies.access_token;
  req.session = { user: null };

  if (token) {
    console.log("Token encontrado:", token);
    try {
      const data = jwt.verify(token, SECRET_JWT_KEY);
      req.session.user = data;
      console.log("User data in session:", req.session.user);
    } catch (error) {
      console.error("Token verification failed:", error.message);
    }
  } else {
    console.log("No token found in cookies");
  }

  next(); // pasa a la siguiente ruta o middleware
});

// Endpoints
app.get("/", (req, res) => {
  const { user } = req.session;
  console.log("User data in / route:", user);
  res.render("index", { user, username: user ? user.username : null });
});

// registro
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  console.log(req.body);
  try {
    const user = await userRepository.create({ username, password });
    console.log("Usuario creado:", user); // Mensaje de depuración adicional

    // usamos jsonwebtoken
    const payload = { id: user._id, username: user.username };
    console.log("Payload del token de registro", payload);

    const token = jwt.sign(payload, SECRET_JWT_KEY, {
      expiresIn: "2h",
    });

    res.cookie("access_token", token, {
      httpOnly: true, // la cookie solo se puede acceder en el servidor
      secure: process.env.NODE_ENV === "production", // la cookie solo se puede acceder en https
      sameSite: "strict", // la cookie solo se puede acceder en el mismo dominio
      maxAge: 60 * 60 * 1000, // la cookie expira en 1 hora
    });

    console.log("El token de registro es:", token);
    res.redirect("/user"); // redirige a /user
  } catch (error) {
    res.status(400).send(error.message);
  }
});

// iniciar sesion
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await userRepository.login({ username, password });
    console.log("Usuario autenticado:", user); // Mensaje de depuración adicional

    // usamos jsonwebtoken
    const payload = { id: user._id, username: user.username };
    console.log("Payload del token de inicio de sesión", payload);

    const token = jwt.sign(payload, SECRET_JWT_KEY, {
      expiresIn: "1h",
    });

    res.cookie("access_token", token, {
      httpOnly: true, // la cookie solo se puede acceder en el servidor
      secure: process.env.NODE_ENV === "production", // la cookie solo se puede acceder en https
      sameSite: "strict", // la cookie solo se puede acceder en el mismo dominio
      maxAge: 60 * 60 * 1000, // la cookie expira en 1 hora
    });

    console.log("El token de inicio de sesión es:", token);
    res.send({ user, token });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

//ruta usuario nuevo
app.get("/user", (req, res) => {
  const { user } = req.session;
  console.log("User data in /user route:", user);
  if (!user) {
    return res.redirect("/");
  }
  res.set("Cache-Control", "no-store");
  res.render("user", { user });
});

// ruta protegida
app.get("/protected", (req, res) => {
  // verifica el token de inicio de sesion
  const { user } = req.session;
  console.log("User data in /protected route:", user);
  if (!user) {
    return res.redirect("/");
  }
  res.set("Cache-Control", "no-store");
  res.render("protected", { user }); // user contiene los datos almacendos en el token de jwt
});

// cerrar sesion
app.post("/logout", (req, res) => {
  res.clearCookie("access_token").json({ message: "Logout successfully" });
});

// borrar usuario
app.delete("/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const deleteUser = await userRepository.delete(id);
    if (deleteUser) {
      res.send({
        message: `El usuario con el id ${id} ha sido elimiminado correctamente`,
      });
    } else {
      res.status(404).send({ message: `El usuario con el id ${id} no existe` });
    }
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});