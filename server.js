const fs = require('fs').promises;
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;
const RUTA_TAREAS = 'tareas.json';
const RUTA_USUARIOS = 'usuarios.json';
const SECRET_KEY = 'clave_secreta';  // Clave para firmar los tokens

// Middleware para procesar JSON
app.use(express.json());

/* ============================ MANEJO DE TAREAS ============================ */
// Función para leer tareas desde el archivo JSON
async function obtenerTareas() {
    try {
        const data = await fs.readFile(RUTA_TAREAS, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') return [];
        throw error;
    }
}

// Función para guardar tareas en el archivo JSON
async function guardarTareas(tareas) {
    await fs.writeFile(RUTA_TAREAS, JSON.stringify(tareas, null, 2));
}

// **Ruta GET para obtener todas las tareas (PROTEGIDA)**
app.get('/tareas', autenticarToken, async (req, res, next) => {
    try {
        const tareas = await obtenerTareas();
        res.json(tareas);
    } catch (error) {
        next(error);
    }
});

// **Ruta POST para agregar una tarea (PROTEGIDA)**
app.post('/tareas', autenticarToken, async (req, res, next) => {
    try {
        const { titulo, descripcion } = req.body;
        if (!titulo || !descripcion) {
            throw new Error('Título y descripción son obligatorios');
        }

        const tareas = await obtenerTareas();
        const nuevaTarea = { id: tareas.length + 1, titulo, descripcion };
        tareas.push(nuevaTarea);

        await guardarTareas(tareas);
        res.status(201).json(nuevaTarea);
    } catch (error) {
        next(error);
    }
});

// **Ruta PUT para actualizar una tarea por ID (PROTEGIDA)**
app.put('/tareas/:id', autenticarToken, async (req, res, next) => {
    try {
        const { id } = req.params;
        const { titulo, descripcion } = req.body;

        const tareas = await obtenerTareas();
        const tareaIndex = tareas.findIndex(t => t.id == id);

        if (tareaIndex === -1) {
            throw new Error('Tarea no encontrada');
        }

        tareas[tareaIndex] = { ...tareas[tareaIndex], titulo, descripcion };
        await guardarTareas(tareas);
        res.json(tareas[tareaIndex]);
    } catch (error) {
        next(error);
    }
});

// **Ruta DELETE para eliminar una tarea por ID (PROTEGIDA)**
app.delete('/tareas/:id', autenticarToken, async (req, res, next) => {
    try {
        const { id } = req.params;

        let tareas = await obtenerTareas();
        const tareasFiltradas = tareas.filter(t => t.id != id);

        if (tareas.length === tareasFiltradas.length) {
            throw new Error('Tarea no encontrada');
        }

        await guardarTareas(tareasFiltradas);
        res.status(200).json({ mensaje: 'Tarea eliminada' });
    } catch (error) {
        next(error);
    }
});

/* ============================ MANEJO DE USUARIOS ============================ */
// Función para leer usuarios desde el archivo JSON
async function obtenerUsuarios() {
    try {
        const data = await fs.readFile(RUTA_USUARIOS, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') return [];
        throw error;
    }
}

// Función para guardar usuarios en el archivo JSON
async function guardarUsuarios(usuarios) {
    await fs.writeFile(RUTA_USUARIOS, JSON.stringify(usuarios, null, 2));
}

// **Ruta de Registro (`POST /register`)**
app.post('/register', async (req, res, next) => {
    try {
        console.log('Intento de registro:', req.body.username);
        const { username, password } = req.body;
        if (!username || !password) {
            throw new Error('Nombre de usuario y contraseña son obligatorios');
        }

        const usuarios = await obtenerUsuarios();
        console.log('Usuarios actuales:', usuarios);

        if (usuarios.find(user => user.username === username)) {
            throw new Error('El usuario ya existe');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        console.log('Contraseña encriptada:', hashedPassword);

        const nuevoUsuario = { id: usuarios.length + 1, username, password: hashedPassword };
        usuarios.push(nuevoUsuario);

        await guardarUsuarios(usuarios);
        console.log('Usuario registrado con éxito:', nuevoUsuario);

        res.status(201).json({ mensaje: 'Usuario registrado exitosamente' });
    } catch (error) {
        next(error);
    }
});

// **Ruta de Inicio de Sesión (`POST /login`)**
app.post('/login', async (req, res, next) => {
    try {
        console.log('Intento de login:', req.body.username);

        const { username, password } = req.body;
        const usuarios = await obtenerUsuarios();
        const usuario = usuarios.find(user => user.username === username);

        if (!usuario || !(await bcrypt.compare(password, usuario.password))) {
            throw new Error('Usuario o contraseña incorrectos');
        }

        const token = jwt.sign({ id: usuario.id, username: usuario.username }, SECRET_KEY, { expiresIn: '1h' });

        console.log('Token generado:', token);
        res.json({ mensaje: 'Inicio de sesión exitoso', token });
    } catch (error) {
        next(error);
    }
});

/* ============================ AUTENTICACIÓN ============================ */
// **Middleware de autenticación**
function autenticarToken(req, res, next) {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            throw new Error('Acceso denegado. Token requerido');
        }

        jwt.verify(token, SECRET_KEY, (err, user) => {
            if (err) {
                throw new Error('Token inválido');
            }
            req.user = user;
            next();
        });
    } catch (error) {
        next(error);
    }
}

// Middleware de manejo de errores
app.use((err, req, res, next) => {
    console.error(`🛑 Error detectado: ${err.message}`);

    if (err.message.includes("Token requerido")) {
        return res.status(401).json({ error: err.message });
    }
    if (err.message.includes("Token inválido")) {
        return res.status(403).json({ error: err.message });
    }
    if (err.message.includes("Tarea no encontrada")) {
        return res.status(404).json({ error: err.message });
    }
    if (err.name === "ValidationError") {
        return res.status(400).json({ error: err.message });
    }

    res.status(500).json({ error: "Ocurrió un error en el servidor" });
});

// **Iniciar el servidor**
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
