const express = require("express");
const router = express.Router();
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const config = require("../config");
const User = require("../model/userModel");

router.use(bodyParser.urlencoded({extended:true}));
router.use(bodyParser.json());

//get all the users

router.get('/users',(req,res)=>{
    User.find({},(err,data)=>{
        if(err) throw err;
        res.send(data);
    });
});

// registering a user
router.post('/register',(req,res)=>{
    //encrypt password
    let hashPassword = bcrypt.hashSync(req.body.password,8);
    User.create(
        {
            name:req.body.name,
            email:req.body.email,
            password:hashPassword,
            phone:req.body.phone,
            role:req.body.role?req.body.role:'User'
        },(err,data)=>{
            if(err) return res.send("Error while registering");
            res.send("Registration Successful!");
        }
    );
});

//Login User

router.post('/login',(req,res)=>{
    User.findOne({email:req.body.email},(err,user)=>{
        if(err) return res.send({auth:false,token:"error while logging in!"});
        if(!user) return res.send({auth:false,token:"No user Found with that email!"});
        else{
            const passIsvalid = bcrypt.compareSync(req.body.password,user.password);
            if(!passIsvalid) return res.send({auth:false,token:"Invalid Password!"});
            //if password is also correct
let token = jwt.sign({id:user._id},config.secret,{expiresIn:86400}); //24hours
res.send({auth:true,token:token});
        }
    });
});

//userInfo
router.get('/userInfo',(req,res)=>{
let token =req.headers['user-access-token'];
if(!token) return res.send({auth:false,token:"No Token Provided!"});
//else jwt verify
jwt.verify(token,config.secret,(err,user)=>{
    if(err) return res.send({auth:false,token:"Invalid Token!"});
    User.findById(user.id,(err,result)=>{
        res.send(result);
    });
});
});

module.exports = router