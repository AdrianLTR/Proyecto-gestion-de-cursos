const sql = require('mssql');

const config = {
    user: 'adrian',            // Reemplaza con tu usuario de SQL Server
    password: '123',     // Reemplaza con tu contraseña
    server: 'localhost\\SQLEXPRESS01',           // O el nombre de tu servidor SQL
    database: 'GestorCursos',      // Reemplaza con el nombre de tu base de datos
    port: 1433,                    // Asegúrate de que este es el puerto correcto
    options: {
        encrypt: false,            // Usa true si estás usando Azure
        trustServerCertificate: true // Agrega esta opción si hay problemas con el certificado SSL
    }
};
const poolPromise = new sql.ConnectionPool(config)
    .connect()
    .then(pool => {
        console.log('Conectado a SQL Server');
        return pool;
    })
    .catch(err => console.log('Error de conexión a SQL Server: ', err));

module.exports = {
    sql, poolPromise
};
