//path module

//Imports

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

//Config json response
app.use(express.json());

app.use(express.urlencoded({extended: false}));

//static file
app.use(express.static("public"));
//Models
const User = require('./models/User');

//Use ejs as view engine
app.set("view engine", "ejs");

//Open Route - Public Route
app.get('/', (req, res) => {
    res.render("login");
    res.status(200).json({msg: "Bem vindo a nossa API"});
});

//signup page test
app.get('/signup', (req, res) => {
    res.render("signup");
    res.status(200).json({msg: "Bem vindo a nossa API"});
});

//Private Route
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id;

    //check if user exists
    const user = await User.findById(id, '-password');
    if(!user) {
        return res.status(404).json({msg: "Usuário não encontrado"});
    }

    res.status(200).json({user});
});

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if(!token) {
        return res.status(401).json({msg: "Acesso negado"});
    }

    try{

        const secret = process.env.SECRET;

        jwt.verify(token, secret);

        next();
        
    }catch(err) {
        res.status(400).json({msg: "Token inválido"});
    }
}

//Register User
app.post('/signup', async(req, res) => {
    const data = {
        name: req.body.username,
        password: req.body.password
    }

    //validation
    if(!data.name) {
        return res.status(422).json({msq: "O nome é obrigatório"});
    }
    /*if(!email) {
        return res.status(422).json({msq: "O email é obrigatório"});
    }*/
    if(!data.password) {
        return res.status(422).json({msq: "A senha é obrigatório"});
    }
    /*if(password !== confirmpassword) {
        return res.status(422).json({msq: "As senhas não conferem"});
    }*/

    //check if user exists
    const userExists = await User.findOne({name: data.name});
    if(userExists) {
        return res.status(422).json({msq: "Usuário já existe"});
    }

    //create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(data.password, salt);

    //create user
    const user = new User({
        name: data.name,
        //email,
        password: passwordHash,
    });

    try {

        await user.save();
        res.status(201).json({msg: "Usuário criado com sucesso"});
        console.log(user);

    } catch(err) {
        console.log(err);
        res.status(500).json({msg: "Erro no servidor. Tente novamente mais tarde"});
    }
});

//login user
app.post("/login", async (req, res) => {
    const data = {
        name: req.body.username,
        password: req.body.password
    }
    console.log(data);
    if(!data.name) {
        return res.status(422).json({msq: "O nome é obrigatório"});
    }
    if(!data.password) {
        return res.status(422).json({msq: "A senha é obrigatório"});
    }

    //check if user exist
    const user = await User.findOne({name: data.name});
    if(!user) {
        return res.status(404).json({msq: "Usuário não encontrado"});
    }

    //check if password match
    const checkPassword = await bcrypt.compare(data.password, user.password);
    if(!checkPassword) {
        return res.status(422).json({msq: "Senha incorreta"});
    }

    try {

        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
    )
    res.render("signup");
    res.status(200).json({msg: "Autenticação realizada com sucesso", token});

    } catch(err) {
        console.log(err);
        res.status(500).json({msg: "Erro no servidor. Tente novamente mais tarde"});
        console.log("não ok");
    }
})

//Credenciais
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.hl8zq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`,

).then(() => {
    app.listen(3000);
    console.log("Conectou com sucesso")
}).catch((err) => console.log(err))

