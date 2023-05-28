const jwt=require("jsonwebtoken")
const {REFRESH_TOKEN_SECRET,ACCESS_TOKEN_SECRET}=require("../config/index")
const RefreshToken = require("../models/token")

class JWTService{
    signAccessToken(payload,expiryTime){
        return jwt.sign(payload,ACCESS_TOKEN_SECRET,{expiresIn:expiryTime});
    }

    signRefreshToken(payload,expiryTime){
        return jwt.sign(payload,REFRESH_TOKEN_SECRET,{expiresIn:expiryTime});
    }

    verifyAccessToken(token){
        return jwt.verify(token,ACCESS_TOKEN_SECRET);
    }
    verifyRefreshToken(token){
        return jwt.verify(token,REFRESH_TOKEN_SECRET);
    }

    async storeRefreshToken(token,userId){
        try {
            const newToken=new RefreshToken({
                token:token,
                userId:userId
            })
            await newToken.save()
        } catch (error) {
          console.log(error)  
        }
    }
}