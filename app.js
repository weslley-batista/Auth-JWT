require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

//config json response
const app = express()
app.use(express.json())

//models
const User = require('./models/User')

//iniciando aplicação
app.get('/', (req, res) => {
    res.status(200).json({ msg: "Bem vindo a API!" })
})

// rota privada
app.get('/user/:id', checkToken, async(req, res) => {
    const id = req.params.id

    //user exists
    // quando essa requisição acontecer pode ser possivel a visialização da senha por parte do usuario
    // para evitar isso colocamos '-password'
    const user = await User.findById(id, '-password') 
    if(!user){
        return res.status(404).json({ msg:'Usuario não encontrado!' })
    }

    res.status(200).json({user})
})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token) {
        return res.status(401).json({ msg:'Acesso negado' })
    }

    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()
    } catch (error) {
        return res.status(400).json({ msg:'Token Invalido' })
    }
}

//Register user
app.post('/auth/register', async(req, res) => {
    const {name, email, password, confirmPassword} = req.body;

    if(!name){
        return res.status(422).json({msg:'O nome é obrigatorio!'})
    }

    if(!email){
        return res.status(422).json({msg:'O email é obrigatorio!'})
    }

    if(!password){
        return res.status(422).json({msg:'A senha é obrigatoria!'})
    }

    if(password != confirmPassword){
        return res.status(422).json({msg:'As senhas são diferentes!'})
    }

    //verify user
    const userExists = await User.findOne({email: email})
    if (userExists) {
        return res.status(422).json({ msg:'o email já existe!' })
    }

    //create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create User
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
        await user.save()
        res.status(201).json({msg: 'usuario criado com sucesso'})
    } catch (error) {
        res.status(500).json({msg: "Erro no servidor",})
    }
    
})

app.post("/auth/login", async(req, res) => {
    const {email, password} = req.body
    
    if(!email){
        return res.status(422).json({msg:'O email é obrigatorio!'})
    }

    if(!password){
        return res.status(422).json({msg:'A senha é obrigatoria!'})
    }

    const user = await User.findOne({email: email})
    if (!user) {
        return res.status(404).json({ msg:'Usuario não encontrado!' })
    }

    // comparar senha da entrada com a do banco de dados
    const checkPassword = await bcrypt.compare(password, user.password)
    if(!checkPassword){
        return res.status(404).json({ msg:'Sua senha está errada' })
    }

    try {
        const secret = process.env.SECRET
        //envio do token junto com o secret do .env
        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        )

        res.status(200).json({msg: "autenticação realizada com sucesso", token})
    } catch (error) {
        console.log(error)
        return res.status(422).json({ msg:'Erro no sevidor, tente mais tarde' })
        
    }
})

// credenciais do .env
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

//conectando ao banco
mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.vgoohhc.mongodb.net/?retryWrites=true&w=majority`,)
.then(
    app.listen(3000, () => {
        console.log('Servidor rodando em http://localhost:3000')
    })
)
.catch((error) => {console.log(error)})

