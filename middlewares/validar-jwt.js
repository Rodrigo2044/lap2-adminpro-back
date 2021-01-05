const jwt = require('jsonwebtoken');
const Usuario = require('../models/usuario');



const validarJWT = (req, res, next) => {

    // Leer el Token
    const token = req.header('x-token');

    if ( !token ) {
        return res.status(401).json({
            ok: false,
            msg: 'No hay token en la petición'
        });
    }

    try {
        
        const { uid } = jwt.verify( token, process.env.JWT_SECRET );
        req.uid = uid;

        next();

    } catch (error) {
        return res.status(401).json({
            ok: false,
            msg: 'Token no válido'
        });
    }
 
}

/*
    Como esto trabaja con calbacks puedo trabajar con async, y puedo esperar a que esa promesa se resuelba,
    cuando yo trabajo de esta manera puedo usar las promesas. Y como no estoy usando el next, hasta aquí va a llegar el procedimiento,
    si sigue es que tengo un usuario de base de datos
*/

const validarADMIN_ROLE = async(req, res, next) => {

    // Puedo intentar leerlo perfectamnete de la request
    const uid = req.uid;

    try {
        const usuarioDB = await Usuario.findById(uid);

        if ( !usuarioDB ) {
            return res.status(404).json({
                ok: false,
                msg: 'Usuario no existe'
            });
        }

        // Voy a mandar un 403 que es un no autorize
        if ( usuarioDB.role !== 'ADMIN_ROLE' ) {
            return res.status(403).json({
                ok: false,
                msg: 'No tiene privilegios para hacer eso'
            });
        }

        next();
        
    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            mag: 'Hable con el adm'
        })
    }
}


const validarADMIN_ROLE_o_MismoUsuario = async(req, res, next) => {

    // Puedo intentar leerlo perfectamnete de la request
    const uid = req.uid;
    // Id que yo quiero modificar
    const id = req.params.id;

    try {
        const usuarioDB = await Usuario.findById(uid);

        if ( !usuarioDB ) {
            return res.status(404).json({
                ok: false,
                msg: 'Usuario no existe'
            });
        }

        // Con el and logico, significaria que es el mismo usuario que se quiere actualizar
        if ( usuarioDB.role === 'ADMIN_ROLE' || uid === id) {
            
            next();

        } else {       
            return res.status(403).json({
                ok: false,
                msg: 'No tiene privilegios para hacer eso'
            });
        }

        
    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            mag: 'Hable con el adm'
        })
    }
}


module.exports = {
    validarJWT,
    validarADMIN_ROLE,
    validarADMIN_ROLE_o_MismoUsuario
}