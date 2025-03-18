import { Router } from "express";
import jwt from "jsonwebtoken";
import { autenticarUsuario } from "../db/index.js";

const router = Router();

// Rota de login
router.post("/login", async (req, res) => {
  console.log("Rota POST /login solicitada");
  try {
    const usuario = await autenticarUsuario(req.body.email, req.body.senha);
    if (usuario !== undefined) {
      const token = jwt.sign({ user: usuario.id, acesso: usuario.acesso }, process.env.SECRET, {
        expiresIn: 30000,
      });
      res.status(202).json({ token: token });
    } else {
      res.status(404).json({ message: "Usuário/Senha incorreta!" });
    }
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message || "Erro!" });
  }
});

// Nova rota /auth
router.get("/auth", verificarAutenticacao, async (req, res) => {
  console.log("Rota GET /auth solicitada");
  try {
    res.status(200).json({ user: `${req.userId}` });
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message || "Erro!" });
  }
});

// Função de verificação de autenticação
function verificarAutenticacao(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1]; // Obtém o token da requisição

  if (!token) {
    return res.status(401).json({ message: "Token não fornecido!" });
  }

  jwt.verify(token, process.env.SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Token inválido!" });
    }

    req.userId = decoded.user; // Adiciona o ID do usuário à requisição
    next(); // Passa o controle para a próxima função ou rota
  });
}

export default router;
