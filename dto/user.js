class UserDTO{
    constructor(user){
        this._id=user.id;
        this.username=user.username;
        this.name=user.name;
    }
}

module.exports=UserDTO;