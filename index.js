require('dotenv').config()
const express     =  require('express')
const mongoose    =  require('mongoose')
const bcrypt      =  require('bcrypt')
const jwt         =  require('jsonwebtoken')
const validator   =  require('validator')
const path        =  require('path')
const hbs         =  require('hbs')
const bodyparser  =  require('body-parser')
const cookieparser = require('cookie-parser')
const { send } = require('process')
const port        =  process.env.PORT || 3001

const app         =  express()

app.set('view engine','hbs')
app.use(cookieparser());
app.use(express.static(__dirname + 'views'));
app.use(express.static(__dirname + '/views'));
app.use(bodyparser.json())
app.use(bodyparser.urlencoded({extended:false}))

mongoose.connect(process.env.DATA_KEY)

const registrationSchema = new mongoose.Schema({
    name : {
        type : String ,
        required : true ,
        trim : true
    },
     email : {
        type : String,
        unique : true ,
        required : true ,
        trim : true ,
        lowercase : true ,
        validate(value){
            if(!validator.isEmail(value)){
                throw new Error("Email is invalid")
            }
        }
     },
      contact_number : {
        type : Number,
        required : true ,
        trim : true
      },

      password: {
        type: String,
        required: true,
        minlength: 7,
        trim: true,
        validate(value) {
            if (value.toLowerCase().includes('password')) {
                throw new Error('Password cannot contain "password"')
            }
        }
    },
    age: {
        type: Number,
        default: 0,
        validate(value) {
            if (value < 0) {
                throw new Error('Age must be a postive number')
            }
        }
    },
    tokens: [{
        token: {
            type: String,
            required: true
        }
    }]
       
})


//  hash password before saving
registrationSchema.pre('save' , async function  (next)  {
    const user = this
    if(this.isModified('password')){
        user.password = await bcrypt.hash(user.password,10)
    }
    next()
})

//for login
registrationSchema.statics.findByCredentials = async (email, password) => {
    const user = await User.findOne({ email })
    if (!user) {
        throw new Error('Unable to login')
    }
    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
        throw new Error('Unable to login')
    }
    return user
}

//for generating token
registrationSchema.methods.generateAuthToken = async function() {
    const user = this
    const token = jwt.sign({_id : user._id},process.env.SECRET_KEY)
    user.tokens = user.tokens.concat({token})
    await user.save()
    return token
}
//for verify token
const auth = async (req, res, next) => {
    try {
        const token = req.cookies.jwt
        const verifyUser = jwt.verify(token , process.env.SECRET_KEY)
        const user = await User.findOne({ _id: verifyUser._id, 'tokens.token': token })
        if (!user) {
            throw new Error()
        }
        console.log(user)
        req.token = token
        req.user = user
        next()
    } catch (e) {
        res.status(401).send({ error: 'Please authenticate.' })
        console.log(e)
    }
}
 //for collection

const User = mongoose.model('User', registrationSchema)

//routes
app.get("/",async (req,res)=>{
     res.render('loginpage.hbs')
})

app.get("/registration",  async (req,res)=>{
      res.render('registration.hbs')
})

app.get('/login/view', auth ,async (req,res)=>{
    // console.log(`this is awesome ${req.cookies.jwt}`)
    res.render('viewinfo')
})

app.get('/logout',auth,async(req,res)=>{
    try{

        //logout from single devices
        // req.user.tokens = req.user.tokens.filter((currentelement)=>{
        //     return currentelement !== req.token
        // })


        //logout for all devices
        req.user.tokens=[]

        res.clearCookie("jwt")
        console.log("logout successfully")
         await req.user.save(
            res.redirect('/')
         )

    }catch(e){
        res.status(500).send(e)
    }

})

app.post("/registration",async(req,res)=>{
     const name = req.body.name 
     const email = req.body.email
     const contact_number = req.body.contact_number
     const age = req.body.age
     const password = req.body.password

     try{
        const newuser = new User()
        newuser.name = name
        newuser.email = email
        newuser.contact_number = contact_number
        newuser.age = age 
        newuser.password = password

        const token = await newuser.generateAuthToken()
        res.cookie("jwt",token,{
            expires : new Date(Date.now() + 3000000),
            httpOnly: true
        })

        await newuser.save()
          
        res.status(201).redirect('/')
     }
     catch(e){
        res.status(400).send(e)
        console.log(e)
     }
})

app.post('/',async(req,res)=>{
    const email = req.body.email
    const password = req.body.password
    try{
        const user = await User.findByCredentials(email,password)
         const token = await user.generateAuthToken()
         res.cookie("jwt",token,{
            expires : new Date(Date.now() + 1000000),
            httpOnly: true
        })

        res.redirect("/login/view")
    }catch(e){
        res.status(500).send("something went wrong")
    }

})


app.listen(port , ()=>{
    console.log(`listening to port ${port}`)
})