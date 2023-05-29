const Joi=require("joi");
const User=require("../models/user")
const bcrypt=require("bcrypt")
const UserDTO = require("../dto/user");
const JWTService = require("../services/JWTServices");

const authController={
    async register(req,res,next){
        //validate user input
        const passwordPattern=/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,25}$/;
        const userRegisterSchema=Joi.object({
            username:Joi.string().min(5).max(30).required(),
            name:Joi.string().max(30).required(),
            email:Joi.string().email().required(),
            password:Joi.string().pattern(passwordPattern).required(),
            confirmPassword:Joi.ref("password")
        })

        const {error}=userRegisterSchema.validate(req.body)
        //if error return error with middleware
        if(error){
            return next(error)
        }
        console.log(req.body)
        //if username or email already register give error
        const {username,name,email,password}=req.body;

        try {
            const emailInUse=await User.exists({email})
            const userInUse=await User.exists({username})

            if (emailInUse){
                const error={
                    status:409,
                    message:"Email already registered, Use another email"
                }
                return next(error);
            }

            if (userInUse){
                const error={
                    status:409,
                    message:"Username already registered, Use another username"
                }
                return next(error);
            }
        } catch (error) {
            return next(error);
        }

        const hashPassword=await bcrypt.hash(password,10);


        let accessToken;
        let refreshToken;
        try{
            const userToRegister=new User({
                username,
                email,
                name,
                password:hashPassword
            })
    
            const user=await userToRegister.save()

            accessToken=JWTService.signAccessToken({_id:user._id,username:user.email},'30m');
            refreshToken=JWTService.signRefreshToken({_id:user._id},'60m');

        }
        catch(error){

        }
      
        //hash password and store in db
        const userDto=new UserDTO(user);
        return res.status(201).json({userDto});
    },
    async login(req,res,next){
        const passwordPattern=/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,25}$/;
        const userLoginSchema=Joi.object({
            username:Joi.string().min(5).max(30).required(),
            password:Joi.string().pattern(passwordPattern).required(),
        })
        const {error}=userLoginSchema.validate(req.body);
        
        if (error){
            return next(error)
        }
        
        const {username,password}=req.body;
        let user;
        try {

            user=await User.findOne({username:username});
            if (!user){
                const error={
                    status:401,
                    message:"Invalid Username or Password",
                    
                }
                return next(error);
            }
            const match=await bcrypt.compare(password,user.password);
            if (!match){
                const error={
                    status:401,
                    message:"Invalid Password",
                }
                return next(error)
            }

        } catch (error) {
            return next(error)
        }
        const userDto=new UserDTO(user)
        return res.status(200).json({user:userDto})
    },
}

module.exports=authController