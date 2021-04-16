
require('dotenv').config();//enviroment variable. Seguir documentacion para implementarla
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const mongoose=require("mongoose");
const encrypt=require("mongoose-encryption");//nivel 2 para encriptar, ver la documentacion para implementarlo
//NIVEL 2 DE SEGURIDAD usaremos para encryptar Secret String Instead of two keys. Esta es una de las muchas formas de encryptar que vienen en la documentacion del paquete npm. 

const app=express();

app.use(express.static("public"));//acceder a carpeta de styles y cosas como imagenes etc
app.set("view engine","ejs");//decriel que renderize usando ejs
app.use(bodyParser.urlencoded({extended:true}));//bodyparser para jalar datos del visualizador del navegador o ejs

mongoose.connect('mongodb://localhost:27017/userDB', {useNewUrlParser: true, useUnifiedTopology: true});//Coenctamos o creamos la base de datos

// const userSchema={//Creamos el schema para la nueva collection
//     email:String,
//     password:String
// }; MODIFICAMOS EL SCHEMA PARA APLICAR EL encrypt

const userSchema= new mongoose.Schema({//ahora es un objeto creado de la clase schema y no un simple json
    email:String,
    password: String
});

//console.log(process.env.SECRET); //asi leeriamos u obtendriamos un dato de env

// const secret="Esteesungransecreto";//renglones para encryptar por el metodo Secret String Instead of two keys de la documentacion del paquete npm segun documentacion
// userSchema.plugin(encrypt,{secret:secret, encryptedFields:["password"]});//Si no especificamos que solo es el password, encriptaria toda la base d datos
//CAMBIAMOS A .env y USAMOS SU FORMATO-- 
userSchema.plugin(encrypt,{secret:process.env.SECRET, encryptedFields:["password"]});

//Es importante encriptar antes de crear el mongoose model
//Al ejecutar el metodo save con mongoose el paquete encryptara y al ejecutar el find decodificara

const User=mongoose.model("User",userSchema);//Creamos el modelo User, recordar que se escribe en singular y la primer letra mayuscula

app.post("/register",function(req,res){//REGISTRAR NUEVO USUARIO
    const newUser=new User({
        email:req.body.username,//Esto se puede hacer gracias a bodyparser
        password:req.body.password
    });
    newUser.save(function(err){
        if(err){
            console.log(err);
        }else{
            res.render("secrets");
        }
    });
});

app.post("/login",function(req,res){//LOGEARSE
    const user=req.body.username;
    const password=req.body.password;

    User.findOne({email:user},function(err,foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){//si encunetra usuario
                if(foundUser.password===password)//revisa que la contrase;a para logear sea la misma registrada en la DB
                {
                    res.render("secrets");
                }else{
                    res.send("Contrase;a erronea");
                }
            }
        }
    }); 
});






app.get("/",function(req,res){
    res.render("home");
});

app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});



app.listen(3000,function(){
    console.log("Server started on port 3000");
})