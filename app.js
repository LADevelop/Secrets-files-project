
//importante seguir el orden de codigo
require('dotenv').config();//enviroment variable. Seguir documentacion para implementarla//SIEMPRE DEBE IR PRIMERO
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const mongoose=require("mongoose");
const session=require("express-session");//seguridad y autenticacion
const passport=require("passport");//seguridad y autenticacion
const passportLocalMongoose=require("passport-local-mongoose");// no se necesita requerir passport-local ya que es dependencia de pass-local-mongoo


//const encrypt=require("mongoose-encryption"); ELIMINADO AL IMPLEMENTAR HASH //nivel 2 para encriptar, ver la documentacion para implementarlo
//NIVEL 2 DE SEGURIDAD usaremos para encryptar Secret String Instead of two keys. Esta es una de las muchas formas de encryptar que vienen en la documentacion del paquete npm. 
//const md5=require("md5"); ELIMINADO PARA IMPLEMENTAR BCRYPT
//OMITIMOS BCRYPT para usar passport, tambien el como usarlos para registrarnos y logearnos
// const bcrypt=require("bcrypt");//nivel 4 HASH Y SALT BCRYPT
// const saltRounds=10;

const app=express();

app.use(express.static("public"));//acceder a carpeta de styles y cosas como imagenes etc
app.set("view engine","ejs");//decriel que renderize usando ejs
app.use(bodyParser.urlencoded({extended:true}));//bodyparser para jalar datos del visualizador del navegador o ejs

app.use(session({//setup session para las cookies
    secret:"Secreto que deve ir en .env",
    resave:false,
    saveUninitialized:false
    //cookie:{secure:true}
}));
app.use(passport.initialize());  //inicializamos paquete passport
app.use(passport.session());//inicializamos el manejo de sesiones con pasport

mongoose.connect('mongodb://localhost:27017/userDB', {useNewUrlParser: true, useUnifiedTopology: true});//Coenctamos o creamos la base de datos
mongoose.set("useCreateIndex", true);//Se agrego para evitar el deprecated warning

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
//userSchema.plugin(encrypt,{secret:process.env.SECRET, encryptedFields:["password"]}); //ELIMINADO AL IMPLEMENTAR HASHING

//Es importante encriptar antes de crear el mongoose model
//Al ejecutar el metodo save con mongoose el paquete encryptara y al ejecutar el find decodificara

userSchema.plugin(passportLocalMongoose)//Le aplicamos un plugin para hash-salt

const User=mongoose.model("User",userSchema);//Creamos el modelo User, recordar que se escribe en singular y la primer letra mayuscula

passport.use(User.createStrategy());//npm documentacion local-mongoose simplified Passport/Passport locacl config/ crea una estrategia local de login

passport.serializeUser(User.serializeUser());//Se usa para las sesiones crea la cookie y almacena las id
passport.deserializeUser(User.deserializeUser());//rompe la galleta y ve quien es el usuario para autenticarlo en el servidor

app.get("/secrets",function(req,res){
    //aqui revisamos con la cookie si el usuario ya esta autenticado y logeado
    if(req.isAuthenticated()){
        res.render("secrets");
    }else{
        res.redirect("/login");
    }
});

app.get("/logout",function(req,res){//"/logout", viene del link del boton de la pagina logout ya que en realidad es link y no boton submit 
    req.logout();//documentacion passport de ahi viene 
    res.redirect("/");
});

app.post("/register",function(req,res){//REGISTRAR NUEVO USUARIO
    User.register({username:req.body.username},req.body.password,function(err,user){//este metodo viene de pasportlocalMongose
    if(err){
        console.log(err);
        res.redirect("/");
    }else{//si no hay errores y se creo el nuevo user
        passport.authenticate("local")(req,res,function(){//autenticamos el nuevo usuario
        res.redirect("/secrets");        //solo ejecuta la funcion si la autenticacion fue exitosa para crear la cookie
        });
    }
    });
    
    
    
    //OMITIDO PARA USAR PASSPORT  Y COOKIES
    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {//NIVEL 4 BCRYPT
    //     // Store hash in your password DB.
    //     //DE AQUI PARA ABAJO LO METES EN ESTA FUNCION PARA BCRYPT
    //     const newUser=new User({
    //         email:req.body.username,//Esto se puede hacer gracias a bodyparser
    //         //password:req.body.password
    //         //password:md5(req.body.password)//uSADO CON HASH
    //         password:hash 
    //     });
    //     //console.log(md5(req.body.password));
    //     newUser.save(function(err){
    //         if(err){
    //             console.log(err);
    //         }else{
    //             res.render("secrets");
    //         }
    //     });//HASTA AQUI PARA BCRYPT
    // });    
});



app.post("/login",function(req,res){//LOGEARSE
    
    const user=new User({//Esto se sabe gracias a la documentacion passportjs.org/docs/login
        username:req.body.username,
        password:req.body.password
    });
    
    req.login(user,function(err){   //metodo login de passport
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req,res,function(){//ayutenticamos al usuario si es que lo encontro en la base de datos
                res.redirect("/secrets");
            })  
        }
    })
    
    //OMITIDO PARA USAR PASSPORT
    // const user=req.body.username;
    // //const password=req.body.password; AL AGREGAR HASH SE MODIFICA
    // //const password=md5(req.body.password);//ESTE ERA SOLO PARA HASH SIN SALR, bcrypt
    // const password=req.body.password;//Lo usamos d nuevo para bcrypt

    // User.findOne({email:user},function(err,foundUser){
    //     if(err){
    //         console.log(err);
    //     }else{
    //         if(foundUser){//si encunetra usuario
    //             bcrypt.compare(password, foundUser.password, function(err, result) {//foundUser.password es el hash-salt que se guardo 
    //                 if (result===true){
    //                     res.render("secrets");
    //                 }else{
    //                     res.send("Contrase;a erronea");
    //                 }
    //             });

    //             //DE AQUI PARA ABAJO ERA SIN BCRYPT PURO HASH
    //             // if(foundUser.password===password)//revisa que la contrase;a para logear sea la misma registrada en la DB
    //             // {
    //             //     res.render("secrets");
    //             // }else{
    //             //     res.send("Contrase;a erronea");
    //             // }
    //         }
    //     }
    // }); 
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