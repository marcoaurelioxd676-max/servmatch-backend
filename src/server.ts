import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken'; // 1. Importação do JWT no topo
import pool from './database.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Middleware para tratamento de JSON malformado
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  if (err instanceof SyntaxError && 'body' in err) {
    res.status(400).json({ error: 'Sintaxe JSON inválida no corpo da requisição.' });
    return;
  }
  next();
});

// Rota de Status
app.get('/api/status', async (_req: Request, res: Response) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({
      status: 'API ServMatch AI online!',
      banco_conectado: true,
      hora_servidor: result.rows[0].now,
    });
  } catch (error: any) {
    res.status(500).json({ status: 'Erro ao conectar ao banco', erro: error.message || error });
  }
});

// 1. Rota de Registo de Utilizadores
app.post('/api/auth/register', async (req: Request, res: Response) => {
  const { name, email, password, role, phone } = req.body || {};

  if (!name || !email || !password) {
    res.status(400).json({ error: 'Nome, email e senha são obrigatórios.' });
    return;
  }

  try {
    const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      res.status(400).json({ error: 'Este email já está registado.' });
      return;
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const newUser = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, phone)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, email, role, phone, created_at`,
      [name, email, password_hash, role || 'client', phone || null]
    );

    res.status(201).json({
      message: 'Utilizador registado com sucesso!',
      user: newUser.rows[0],
    });
  } catch (error: any) {
    console.error('ERRO DETALHADO NO BANCO:', error);
    res.status(500).json({ 
      error: 'Erro interno ao registar utilizador.',
      detalhe: error.message || String(error)
    });
  }
});

// 2. Rota de Login de Utilizadores (AQUI ENTRA O SEGUNDO CÓDIGO)
app.post('/api/auth/login', async (req: Request, res: Response) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    res.status(400).json({ error: 'Email e senha são obrigatórios.' });
    return;
  }

  try {
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      res.status(401).json({ error: 'Credenciais inválidas.' });
      return;
    }

    const user = userResult.rows[0];

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      res.status(401).json({ error: 'Credenciais inválidas.' });
      return;
    }

    const jwtSecret = process.env.JWT_SECRET || 'chave_backup_desenv';
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      jwtSecret,
      { expiresIn: '8h' }
    );

    res.json({
      message: 'Login efetuado com sucesso!',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        phone: user.phone,
      },
    });
  } catch (error: any) {
    console.error('ERRO NO LOGIN:', error);
    res.status(500).json({
      error: 'Erro interno ao realizar login.',
      detalhe: error.message || String(error),
    });
  }
});

// Inicialização do Servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
});