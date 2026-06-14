require('dotenv').config(); 
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json()); 

const limitadorSeguranca = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: { erro: 'Muitas tentativas de login/cadastro detectadas. Tente novamente em 15 minutos.' },
    standardHeaders: true, 
    legacyHeaders: false, 
});

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

app.post('/cadastro', limitadorSeguranca, async (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).json({ erro: 'E-mail e senha são obrigatórios!' });
    }

    try {
        const senhaCriptografada = await bcrypt.hash(senha, 10);
        const query = 'INSERT INTO usuarios (email, senha) VALUES (?, ?)';
        
        pool.query(query, [email, senhaCriptografada], (err, results) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ erro: 'Este e-mail já está cadastrado!' });
                }
                return res.status(500).json({ erro: 'Erro interno no banco de dados.' });
            }

            res.status(201).json({ mensagem: 'Usuário cadastrado com sucesso de forma segura!' });
        });

    } catch (erro) {
        res.status(500).json({ erro: 'Erro ao processar o cadastro.' });
    }
});

app.post('/login', limitadorSeguranca, async (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).json({ erro: 'E-mail e senha são obrigatórios!' });
    }

    try {
        const query = 'SELECT * FROM usuarios WHERE email = ?';
        
        pool.query(query, [email], async (err, results) => {
            if (err) {
                return res.status(500).json({ erro: 'Erro interno no banco de dados.' });
            }

            if (results.length === 0) {
                return res.status(401).json({ erro: 'E-mail ou senha incorretos!' });
            }

            const usuario = results[0];
            const senhaCorreta = await bcrypt.compare(senha, usuario.senha);

            if (!senhaCorreta) {
                return res.status(401).json({ erro: 'E-mail ou senha incorretos!' });
            }

            const token = jwt.sign(
                { id: usuario.id }, 
                process.env.JWT_SECRET, 
                { expiresIn: '1h' }
            );

            res.json({ 
                mensagem: 'Login realizado com sucesso!',
                token: token
            });
        });

    } catch (erro) {
        res.status(500).json({ erro: 'Erro ao processar o login.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
});