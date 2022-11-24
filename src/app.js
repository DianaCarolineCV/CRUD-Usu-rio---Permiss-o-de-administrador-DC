import pkg from "bcryptjs";
import express from "express";
import { v4 as uuidv4 } from "uuid";
import users from "./database.js";
import jwt from "jsonwebtoken";
const { hash, compare } = pkg;
const app = express();
app.use(express.json());
const Port = 3000;

const createUserService = async ({ name, email, password, isAdm }) => {
  const hashedPassword = await hash(password, 10);
  const newUser = {
    name,
    email,
    createdOn: new Date(),
    updatedOn: new Date(),
    uuid: uuidv4(),
    isAdm,
    password: hashedPassword,
  };

  users.push(newUser);

  return [201, newUser];
};

const userLoginService = async (email, password) => {
  const user = users.find((element) => element.email === email);

  if (!user) {
    return [401, { message: "Email invalid or password invalid" }];
  }
  const passwordMatch = await compare(password, user.password);

  if (!passwordMatch) {
    return [401, { message: "Email invalid or password invalid" }];
  }

  const token = jwt.sign({ email }, "SECRET_KEY", {
    expiresIn: "24h",
    subject: user.uuid,
  });

  return [200, { token }];
};

const listUsersService = () => {
  return [200, users];
};

const specificUserService = (user) => {
  return [200, users[user]];
};

const deleteUserService = (id) => {
  const userIndex = users.findIndex((element) => element.uuid === id);
  users.splice(userIndex, 1);
  return [204, {}];
};

const updateUserService = async (id, { name, email, password }) => {
  const user = users.find((element) => element.uuid === id);
  const userIndex = users.findIndex((element) => element.uuid === id);

  const userUpdated = {
    name: name ? name : user?.name,
    email: email ? email : user?.email,
    createdOn: user?.createdOn,
    updatedOn: new Date(),
    uuid: uuidv4(),
    isAdm: user?.isAdm,
    password: password ? await hash(password, 10) : user?.password,
  };

  users[userIndex] = {
    ...userUpdated,
  };

  return [200, users[userIndex]];
};

const verifyEmailExistsMiddleware = (req, res, next) => {
  const foundUserEmail = users.find((e) => e.email === req.body.email);

  if (foundUserEmail) {
    return res.status(409).json({ message: "E-mail already registered." });
  }

  return next();
};

const verifyAdmMiddleware = (req, res, next) => {
  const authToken = req.headers.authorization;

  if (!authToken) {
    return res.status(401).json({ message: "Missing authorization headers" });
  }

  const token = authToken.split(" ")[1];

  jwt.verify(token, "SECRET_KEY", (error, decoded) => {
    if (error) {
      return res.status(403).json({ message: "Invalid token" });
    }

    const userId = decoded.sub;
    const user = users.find((element) => element.uuid === userId);

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    if (user.isAdm === false) {
      return res.status(403).json({ message: "Missing admin permissions" });
    }
    return next();
  });
};

const verifyTokenAuthorizationMiddleware = (req, res, next) => {
  const authToken = req.headers.authorization;

  if (!authToken) {
    return res.status(401).json({ message: "Missing authorization headers" });
  }

  const token = authToken.split(" ")[1];

  jwt.verify(token, "SECRET_KEY", (error, decoded) => {
    if (error) {
      return res.status(403).json({ message: "Invalid token" });
    }

    const foundUser = decoded.sub;
    const userIndex = users.findIndex((element) => element.uuid === foundUser);

    if (userIndex === -1) {
      return res.status(403).json({ message: "User not found" });
    }
    req.userIndex = userIndex;
  });

  return next();
};

const verifyIsAdmUpdateDeleteMiddleware = (req, res, next) => {
  const user = users[req.userIndex];
  if (!user.isAdm && req.params.uuid !== user.uuid) {
    return res.status(403).json({ message: "Missing admin permissions" });
  }
  return next();
};

const createUserController = async (req, res) => {
  const [status, newUser] = await createUserService(req.body);

  const user = {
    name: newUser.name,
    email: newUser.email,
    isAdm: newUser.isAdm,
    uuid: newUser.uuid,
    createdOn: newUser.createdOn,
    updatedOn: newUser.updatedOn,
  };

  return res.status(status).json(user);
};

const userLoginController = async (req, res) => {
  const { email, password } = req.body;

  const [status, token] = await userLoginService(email, password);

  return res.status(status).json(token);
};

const listUsersController = (req, res) => {
  const [status, user] = listUsersService();

  return res.status(status).json(user);
};

const specificUserController = (req, res) => {
  const [status, data] = specificUserService(req.userIndex);

  const userFound = {
    uuid: data.uuid,
    name: data.name,
    email: data.email,
    isAdm: data.isAdm,
    createdOn: data.createdOn,
    updatedOn: data.updatedOn,
  };
  return res.status(status).json(userFound);
};

const deleteUserController = (req, res) => {
  const [status, user] = deleteUserService(req.params.uuid);
  return res.status(status).json(user);
};

const updateUserController = async (req, res) => {
  const [status, user] = await updateUserService(req.params.uuid, req.body);

  const userFound = {
    name: user.name,
    email: user.email,
    isAdm: user.isAdm,
    uuid: user.uuid,
    createdOn: user.createdOn,
    updatedOn: user.updatedOn,
  };

  return res.status(status).json(userFound);
};

app.post("/users", verifyEmailExistsMiddleware, createUserController);
app.post("/login", userLoginController);
app.get("/users", verifyAdmMiddleware, listUsersController);
app.get(
  "/users/profile",
  verifyTokenAuthorizationMiddleware,
  specificUserController
);
app.patch(
  "/users/:uuid",
  verifyTokenAuthorizationMiddleware,
  verifyIsAdmUpdateDeleteMiddleware,
  updateUserController
);
app.delete(
  "/users/:uuid",
  verifyTokenAuthorizationMiddleware,
  verifyIsAdmUpdateDeleteMiddleware,
  deleteUserController
);

app.listen(Port, () => {
  console.log(`App rodando em http://localhost:${Port}`);
});

export default app;
