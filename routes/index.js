const express=require("express");
const authController=require("../controller/authController");
const app = express.Router();

app.get("/test",(req,res)=>{
    res.json({message:"Testing Successful"})
})

//user
//register
app.post("/register",authController.register)
//login
app.post("/login",authController.login);

module.exports=app