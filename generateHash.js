const bcrypt = require('bcryptjs');

async function generateHashedPassword(password) {
    try {
        const hashedPassword = await bcrypt.hash(password, 10); // 10 es el número de saltos
        console.log('Contraseña original:', password);
        console.log('Hash generado:', hashedPassword);
    } catch (err) {
        console.error('Error al generar el hash:', err);
    }
}

// Reemplaza 'tu_contraseña' con la contraseña que quieres hashear
generateHashedPassword('Adrian1310');
