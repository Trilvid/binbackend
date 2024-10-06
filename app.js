const express = require('express')
const cors = require('cors')
const dotenv = require('dotenv')
const mongoose = require('mongoose')
const User = require('./models/user.model')
const Story = require('./models/storyModel')
const jwt = require('jsonwebtoken')
const path = require('path')
var serveStatic = require('serve-static')
const crypto = require('crypto')
dotenv.config()
const fs = require('fs');
const fileUpload = require('express-fileupload');
const { promisify } = require('util');

const app = express()

app.use(cors())

app.use(express.json({ limit: '10mb' }));
app.use(fileUpload({
    limits: { fileSize: 50 * 1024 * 1024 }
}));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(serveStatic(path.join(process.cwd(), '/dist')))
app.get(
  [
    '/',
    '/dashboard',
    '/myprofile',
    '/login',
    '/signup',
    '/withdraw',
    '/plans',
    '/referrals',
    '/admin',
    '/fundwallet',
    '/transactions',
    '/investments',
    '/deposit',
    '/checkout',
    '/withdrawlogs',
    '/faq',
    '/about',
    '/policy',
    '/buybitcoin',
    '/users/:id/verify/:token',
    '/admin',
    '/ref_register/:ref',
    '/resetpassword/:token'
  ],
  (req, res) => res.sendFile(path.join(process.cwd(), '/dist/index.html'))
)
app.use('/static', express.static('dist/static'))

app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

const port = process.env.PORT || 5000

app.use(express.json())

mongoose.set('strictQuery', false)
mongoose.connect(process.env.ATLAS_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB', error);
  });
// mongoose.connect(process.env.ATLAS_URI, console.log('database is connected'))



app.get('/api/verify', async (req, res) => {
  const token = req.headers['x-access-token']
  try {
    const decode = jwt.verify(token, 'secret1258')
    const email = decode.email
    const user = await User.findOne({ email: email })
    if (user.rememberme === true) {
      res.json({
        status: 'ok',
      })
    }
    else {
      res.json({
        status: 'false',
      })
    }
  } catch (error) {
    res.json({ status: `error ${error}` })
  }
})

const createToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  })
};

const success = (statusCode, res, user, message) => {
  const token = createToken(user.id);
  const url = `${process.env.BASE_URL}auth/${user._id}/verify/${token}`;

  res.cookie('jwt', token, {
    expires: new Date(
      Date.now() + 30 * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    // secure: req.secure || req.headers['x-access-token'] === 'http'
  });

  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    role: user.role,
    message,
    url,
    user
  });
}
  // protecting the routes
  app.use = async (req, res, next) => {
    let token;
  
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    }
  
    if (!token) {
      res.status(401).json({
        message: "You are not Logged in!"
      })
    }
      
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    
    const currentUser = await User.findById(decoded.id);
  
    if (!currentUser) {
      res.status(401).json({
        message: "Sorry This account does not exists!"
      })
    }
    
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      res.status(401).json({
        message: "This User recently changed password! please login again"
      })
    }
    
    req.user = currentUser;
    return next()
  }
  
  app.use = (...roles) => {
  return (req, res, next)  => { 
  
    if (!roles.includes(req.user.role)) {
      throw new AppError("unauthorized", 'you do not have permission to perform this action', 401)
    }
  next();
  }
  }

// get all users
  app.get('/api/', async (req, res) => {

    const data = await User.find()
    return res.status(200).json({
      total: data.length,
    data
  })
  })

  app.get('/api/:id', async (req, res) => {
    const data = await User.findById(req.user.id, {})
   return res.status(200).json(data)

})

  // new user
  app.post('/api/signup', async (req, res) => {
    
    const user = await User.create({
      username: req.body.username,
      email: req.body.email,
      password: req.body.password,
      role: req.body.role,
      active: req.body.active,
      photo: "https://res.cloudinary.com/ult-bank/image/upload/v1685139259/t9tjkxnb3nrmtjuizftp.png",

    })

    return success(201, res, user, "Account created" )
    
})

  // login module 
  app.post('/api/signin', async (req, res) => {
    const {email, password} = req.body;

    const user = await User.findOne({email}).select('+password');

    if(!email || !password) {
      // throw new AppError(401, "email or password cannot be empty", 401)
      return res.status(401).json({msg: "email or password cannot be empty"})
    }
    
   else if (!user || !(await user.correctPassword(password, user.password))) {
      // throw new AppError(401, "invalid login details try again", 401)
      return res.status(401).json({msg: "invalid login details try again"})
    }

    else if(user.verified === false) {
      return res.status(400).json({msg: "your email is not verified, please go to your eamil and verify"})
      // throw new AppError(400, "your email is not verified, please go to your eamil and verify", 400)
    }

    else {
    return success(200, res, user, "sucessfully logged in")
    }

  })

  app.get('/api/stories/allstories', async (req, res) => {

    const { category } = req.query;

    let stories;
        
    if (category) {
        stories = await Story.find({ category }); 
    } else {
        stories = await Story.find({});
    }

    res.status(200).json({
        success: true,
        total: stories.length,
        stories
    })

})


app.get('/api/stories/:id', async (req, res) => {
  
  const story = await Story.findById(req.params.id, {})

  if(!story) {
      // throw new AppError("Not Found", "This story has been deleted", 404)
      return res.status(404).json({msg: "NOt Found", error: "this story has been deleted"})
  }

  const author = story.user_id

  // success(200, res, story, author.username)
  return res.status(200).json({ story, author: author.username})
  
})



app.post('/api/stories/newpost', async (req, res) => {
  try {
    let token;
  
    // 1. Check if the token exists in the authorization header
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    }
  
    // 2. If no token is found, return a 401 error
    if (!token) {
      return res.status(401).json({
        message: "You are not logged in!",
      });
    }
  
    // 3. Verify the token and decode the user ID
    let decoded;
    try {
      decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({
        message: "Invalid token. Please log in again!",
      });
    }
  
    // 4. Find the user based on the decoded token ID
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return res.status(401).json({
        message: "The user belonging to this token no longer exists!",
      });
    }
  
    // 5. Check if the user changed their password after the token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return res.status(401).json({
        message: "User recently changed password. Please log in again.",
      });
    }

    req.user = currentUser;
    
      const { title, story, category, image } = req.body;

      const uploadsDir = path.join(__dirname, '..', 'uploads');

      if (!fs.existsSync(uploadsDir)) {
          fs.mkdirSync(uploadsDir);
      }

      let imagePath = '';
      if (image) {
          const base64Data = image.replace(/^data:image\/\w+;base64,/, ''); 
          const buffer = Buffer.from(base64Data, 'base64');

          const imageName = `${Date.now()}-image.png`;
          imagePath = `/uploads/${imageName}`;
          fs.writeFileSync(path.join(uploadsDir, imageName), buffer); 
      }

      // Create the new story in the database
      const newStory = new Story({
          title,
          user_id: req.user._id,
          story,
          category,
          image: imagePath,
          geolocation: req.body.geolocation
      });

      await newStory.save();
      res.status(201).json({ message: 'Post created successfully!', newStory });

  } catch (error) {
      console.error('Error creating story:', error);
      res.status(500).json({ message: 'Server error. Could not create post.' });
  }
});



app.delete('/api/stories/:id', async (req, res) => {
  const story = await Story.findByIdAndDelete(req.params.id)

  if(!story) {
      // throw new AppError("Not Found", "Sorry This Accout does not exist ", 404)
      return res.status(204).json({msg: "Not found", error: "sorry this story does not exists"})
  }

  // success(204, res, null)
  res.status(204).json({success: true, message: 'Story deleted successfully' })
})  


app.patch('/api/stories/:id', async (req, res) => {

  const id  = req.params;
  const { title, story, category } = req.body;

  // Find the story by ID and update it
  const updatedStory = await Story.findByIdAndUpdate(req.params.id, {
      title,
      story,
      category,
  }, { 
      new: true,
      runValidators: true, }); 

  if (!updatedStory) {
      return res.status(404).json({ success: false, message: 'Story not found' });
  }

  // success(200, res, updatedStory, "author.firstname")
  res.status(200).json({ success: true, story: updatedStory });

})


















module.exports = app