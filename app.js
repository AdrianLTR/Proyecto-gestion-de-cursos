const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const http = require('http');
const socketIo = require('socket.io');
const { sql, poolPromise } = require('./db');

const app = express();

// Configurar multer para subir archivos
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/uploads');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// Configuración de la sesión
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }  // Usar `true` en producción con HTTPS
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

const server = http.createServer(app);
const io = socketIo(server);

io.on('connection', (socket) => {
    console.log('Nuevo cliente conectado');
    socket.on('disconnect', () => {
        console.log('Cliente desconectado');
    });
});

// Middleware para proteger rutas
function requireLogin(req, res, next) {
    if (!req.session.userId) {
        res.redirect('/login');
    } else {
        next();
    }
}

// Middleware para verificar si el usuario es administrador
function requireAdmin(req, res, next) {
    if (req.session.userRole !== 'admin') {
        return res.status(403).send('Acceso denegado: Solo los administradores pueden acceder a esta sección.');
    }
    next();
}

// Ruta para mostrar la página de login
app.get('/login', (req, res) => {
    res.render('login');  // Renderiza la vista login.ejs
});

// Ruta para la página de inicio
app.get('/', (req, res) => {
    res.render('inicio'); // Renderiza la vista de bienvenida
});

// Ruta para procesar el login
app.post('/login', async (req, res) => {
    try {
        const pool = await poolPromise;
        const { correo, contraseña } = req.body;

        const result = await pool.request()
            .input('correo', sql.NVarChar, correo)
            .query('SELECT * FROM UserLogin WHERE correo = @correo');

        const userLogin = result.recordset[0];

        if (userLogin && await bcrypt.compare(contraseña, userLogin.contraseña)) {
            req.session.userId = userLogin.usuario_id;  // Verifica que esta columna exista en la tabla UserLogin
            req.session.userRole = userLogin.rol;
            req.session.username = userLogin.nombre;  // Guarda el nombre de usuario en la sesión

            if (userLogin.rol === 'admin') {
                res.redirect('/gestor');
            } else {
                res.redirect('/dashboard');
            }
        } else {
            res.status(401).send('Correo o contraseña incorrectos');
        }
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para cerrar sesión
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send({ message: err.message });
        }
        res.redirect('/login');
    });
});

// Ruta principal para mostrar cursos y usuarios solo para administradores
app.get('/gestor', requireLogin, requireAdmin, async (req, res) => {
    try {
        const pool = await poolPromise;
        const cursos = await pool.request().query('SELECT * FROM Cursos');
        const usuarios = await pool.request().query('SELECT * FROM Usuarios');
        res.render('index', { cursos: cursos.recordset, usuarios: usuarios.recordset, userRole: req.session.userRole });
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para registrar un nuevo usuario
app.post('/register', upload.single('foto'), async (req, res) => {
    try {
        const pool = await poolPromise;
        const { nombre, correo, contraseña } = req.body;
        const foto = req.file ? `/uploads/${req.file.filename}` : null;

        // Insertar en la tabla Usuarios
        const result = await pool.request()
            .input('nombre', sql.NVarChar, nombre)
            .input('foto', sql.NVarChar, foto)
            .query('INSERT INTO Usuarios (nombre, foto) OUTPUT INSERTED.id AS usuario_id');

        const usuario_id = result.recordset[0].usuario_id;

        // Hash de la contraseña
        const hashedPassword = await bcrypt.hash(contraseña, 10);

        // Insertar en la tabla UserLogin
        await pool.request()
            .input('usuario_id', sql.Int, usuario_id)
            .input('correo', sql.NVarChar, correo)
            .input('contraseña', sql.NVarChar, hashedPassword)
            .query('INSERT INTO UserLogin (usuario_id, correo, contraseña) VALUES (@usuario_id, @correo, @contraseña)');
        
        res.redirect('/login');
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para inscribir un usuario en un curso
app.post('/inscribir', requireLogin, async (req, res) => {
    try {
        const pool = await poolPromise;
        const { usuario_id, curso_id } = req.body;

        // Insertar la inscripción en la tabla Inscripciones
        await pool.request()
            .input('usuario_id', sql.Int, usuario_id)
            .input('curso_id', sql.Int, curso_id)
            .query('INSERT INTO Inscripciones (usuario_id, curso_id) VALUES (@usuario_id, @curso_id)');
        
        io.emit('notificacion', `El usuario con ID ${usuario_id} se inscribió en el curso ${curso_id}`);

        res.redirect('/gestor');  // Redirigir de vuelta a la página principal después de la inscripción
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para enviar un mensaje a un usuario
app.post('/enviarMensaje', requireLogin, requireAdmin, async (req, res) => {
    try {
        const { usuario_id, contenido } = req.body;  // Aquí 'usuario_id' se refiere al ID del destinatario

        const pool = await poolPromise;
        const remitente_id = req.session.userId;

        await pool.request()
            .input('remitente_id', sql.Int, remitente_id)
            .input('destinatario_id', sql.Int, usuario_id)  // Cambiado de 'usuario_id' a 'destinatario_id'
            .input('contenido', sql.NVarChar, contenido)
            .query('INSERT INTO Mensajes (remitente_id, destinatario_id, contenido, fecha) VALUES (@remitente_id, @destinatario_id, @contenido, GETDATE())');

        res.redirect('/gestor');
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para mostrar mensajes
app.get('/mensajes', requireLogin, async (req, res) => {
    try {
        const pool = await poolPromise;
        const mensajes = await pool.request()
            .input('usuario_id', sql.Int, req.session.userId)
            .query('SELECT * FROM Mensajes WHERE destinatario_id = @usuario_id');

        res.render('mensajes', { mensajes: mensajes.recordset });
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para el panel de control
app.get('/dashboard', requireLogin, async (req, res) => {
    try {
        const pool = await poolPromise;
        const cursos = await pool.request()
            .input('usuario_id', sql.Int, req.session.userId)
            .query('SELECT C.* FROM Cursos C INNER JOIN Inscripciones I ON C.id = I.curso_id WHERE I.usuario_id = @usuario_id');

        const mensajes = await pool.request()
            .input('usuario_id', sql.Int, req.session.userId)
            .query('SELECT * FROM Mensajes WHERE destinatario_id = @usuario_id');

        // Pasa el nombre de usuario (o cualquier otro dato necesario) a la vista
        res.render('dashboard', {
            cursos: cursos.recordset,
            mensajes: mensajes.recordset,
            username: req.session.username // Asegúrate de que el nombre de usuario esté en la sesión
        });
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para generar certificado
app.get('/certificado/:curso_id', requireLogin, async (req, res) => {
    try {
        const pool = await poolPromise;
        const { curso_id } = req.params;

        const progreso = await pool.request()
            .input('usuario_id', sql.Int, req.session.userId)
            .input('curso_id', sql.Int, curso_id)
            .query('SELECT porcentaje_completado FROM Progreso WHERE usuario_id = @usuario_id AND curso_id = @curso_id');

        if (progreso.recordset[0].porcentaje_completado === 100) {
            res.render('certificado', { curso_id });
        } else {
            res.status(403).send('Aún no has completado este curso');
        }
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para agregar un curso
app.post('/agregarCurso', requireLogin, async (req, res) => {
    try {
        const pool = await poolPromise;
        const { nombre, descripcion } = req.body;
        await pool.request()
            .input('nombre', sql.NVarChar, nombre)
            .input('descripcion', sql.NVarChar, descripcion)
            .query('INSERT INTO Cursos (nombre, descripcion) VALUES (@nombre, @descripcion)');
        res.redirect('/gestor');
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para registrar un usuario (utilizando el sistema existente)
app.post('/registrarUsuario', requireLogin, upload.single('foto'), async (req, res) => {
    try {
        const pool = await poolPromise;
        const { nombre, correo } = req.body;
        const foto = req.file ? `/uploads/${req.file.filename}` : null;

        await pool.request()
            .input('nombre', sql.NVarChar, nombre)
            .input('correo', sql.NVarChar, correo)
            .input('foto', sql.NVarChar, foto)
            .query('INSERT INTO Usuarios (nombre, correo, foto) VALUES (@nombre, @correo, @foto)');
        
        res.redirect('/gestor');
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para editar un usuario (muestra el formulario de edición)
app.get('/editarUsuario/:id', requireLogin, async (req, res) => {
    try {
        const pool = await poolPromise;
        const usuario = await pool.request()
            .input('id', sql.Int, req.params.id)
            .query('SELECT * FROM Usuarios WHERE id = @id');
        res.render('editarUsuario', { usuario: usuario.recordset[0] });
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para manejar la edición de un usuario (procesa el formulario de edición)
app.post('/editarUsuario/:id', requireLogin, upload.single('foto'), async (req, res) => {
    try {
        const pool = await poolPromise;
        const { nombre, correo } = req.body;
        const foto = req.file ? `/uploads/${req.file.filename}` : req.body.existingFoto;

        await pool.request()
            .input('id', sql.Int, req.params.id)
            .input('nombre', sql.NVarChar, nombre)
            .input('correo', sql.NVarChar, correo)
            .input('foto', sql.NVarChar, foto)
            .query('UPDATE Usuarios SET nombre = @nombre, correo = @correo, foto = @foto WHERE id = @id');
        res.redirect('/gestor');
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para eliminar un usuario
app.post('/eliminarUsuario/:id', requireLogin, async (req, res) => {
    try {
        const pool = await poolPromise;

        await pool.request()
            .input('usuario_id', sql.Int, req.params.id)
            .query('DELETE FROM Inscripciones WHERE usuario_id = @usuario_id');

        await pool.request()
            .input('id', sql.Int, req.params.id)
            .query('DELETE FROM Usuarios WHERE id = @id');

        res.redirect('/gestor');
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para editar un curso (muestra el formulario de edición)
app.get('/editarCurso/:id', requireLogin, async (req, res) => {
    try {
        const pool = await poolPromise;
        const curso = await pool.request()
            .input('id', sql.Int, req.params.id)
            .query('SELECT * FROM Cursos WHERE id = @id');
        res.render('editarCurso', { curso: curso.recordset[0] });
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para manejar la edición de un curso (procesa el formulario de edición)
app.post('/editarCurso/:id', requireLogin, async (req, res) => {
    try {
        const pool = await poolPromise;
        const { nombre, descripcion } = req.body;
        await pool.request()
            .input('id', sql.Int, req.params.id)
            .input('nombre', sql.NVarChar, nombre)
            .input('descripcion', sql.NVarChar, descripcion)
            .query('UPDATE Cursos SET nombre = @nombre, descripcion = @descripcion WHERE id = @id');
        res.redirect('/gestor');
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Ruta para mostrar el curso asignado
app.get('/curso/:id', requireLogin, async (req, res) => {
    try {
        const pool = await poolPromise;
        const { id } = req.params;

        const curso = await pool.request()
            .input('id', sql.Int, id)
            .query('SELECT * FROM Cursos WHERE id = @id');

        if (curso.recordset.length === 0) {
            return res.status(404).send('Curso no encontrado');
        }

        res.render('curso', { curso: curso.recordset[0] });
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});


// Ruta para ver el progreso de los cursos
app.get('/progresoCursos', requireLogin, async (req, res) => {
    try {
        const pool = await poolPromise;
        const usuario_id = req.session.userId;

        const progreso = await pool.request()
            .input('usuario_id', sql.Int, usuario_id)
            .query(`
                SELECT C.nombre, P.porcentaje_completado
                FROM Progreso P
                INNER JOIN Cursos C ON P.curso_id = C.id
                WHERE P.usuario_id = @usuario_id
            `);

        res.render('progresoCursos', { progreso: progreso.recordset });
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});



// Ruta para eliminar un curso
app.post('/eliminarCurso/:id', requireLogin, async (req, res) => {
    try {
        const pool = await poolPromise;
        await pool.request()
            .input('id', sql.Int, req.params.id)
            .query('DELETE FROM Cursos WHERE id = @id');
        res.redirect('/gestor');
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Iniciar el servidor en el puerto configurado
const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`Servidor corriendo en el puerto ${port}`));
