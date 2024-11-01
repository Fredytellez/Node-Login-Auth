// importamos DBLocal que es una base de datos local - Metodos para actuializar modificar datos etc en memoria del pc
import DBLocal from 'db-local';
// donde guarda los datos
const {Schema} = new DBLocal({path:'./db'});
// Para encriptar la contraseña
import crypto from 'node:crypto'
import bcrypt from 'bcrypt';
import {SALT_ROUNDS} from './config.js';

// creacion del esquema
const User = Schema('User', {
    _id: {type: String, required: true},
    username: {type: String, required: true},
    password: {type: String, required: true},
});

//se exporta la clase 
export class userRepository {
    static async create ({username, password}) {
        // validacion de username {Opcional: usar Zod}
        Validation.username(username)
        Validation.password(password)

        // Asegurarse que el username no existe
        const user = User.findOne({ username })
        if (user) throw new Error('Username already exists')
        
        // randomUUID tiene problemas de rendimiendo en algunas bases de datos - problemas con la indexacion
        // Muchas bases de datos ya generan ids, por ejemplo MongoDB
        const id = crypto.randomUUID()
        // Para codificar la constraseña
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

        // Este create no es asincrono por que la base de datos es local
        User.create({ 
            _id: id, 
            username,
            password: hashedPassword
        }).save()

        return id

    }
    static async login ({username, password}) {
        Validation.username(username)
        Validation.password(password)   

        // Valida que existe el usuario
        const user = User.findOne({ username })
        if (!user) throw new Error("Username does not exist")

        // Compara las constraseñas   
        const isValid = await bcrypt.compare(password, user.password)
        if (!isValid) throw new Error('Invalid password')

        // no muestra el password en la respuesta    
        const {password: _, ...publicUser} = user

        // retorna el usuario    
        return publicUser
    }
    static async delete(id) {
        // busca el id del usuario
        const user = await User.findOne({_id: id})
        // si no existe el usuario
        if (!user) throw new Error('User not found')

        // elimina el usuario y retorna true si se ha eliminado correctamente
        await User.remove({_id: id})
        // Retorna true si se ha eliminado correctamente
        return true
    }
}

class Validation {

    static username (username) {
        if (typeof username !== 'string') throw new Error('Username must be a string')
        if (username.length < 4) throw new Error('Username must be at least 4 characters')
    }

    static password (password) {
        if (typeof password !== 'string') throw new Error('Password must be a string')
        if (password.length < 8) throw new Error('Password must be at least 8 characters')
    }

}