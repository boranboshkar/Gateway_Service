
import { Request, Response,NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import bcrypt from 'bcrypt';

import User from './models/user.js';

// JWT Authentication Middleware
export async function authenticate(req: Request, res: Response, next: NextFunction) {
  console.log(`Authenticating: ${req.method} ${req.path}`);
  const token = req.cookies.token;
  if (!token) { 
    return res.status(401).send('Access denied. No token provided.');
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET) as jwt.JwtPayload;
    const username = payload.username;

    // Fetch the user details from the database by username
    const user = await User.findOne({ username: username }).lean();
    if (!user) {
      return res.status(401).send('User not found.');
    }

    req.user = {
      _id: user._id.toString(),
      username: user.username,
      permission: user.permission, 
    };
    // On successful authentication
console.log(`Authentication successful for user ${req.user._id} , username: ${user.username}, user permission: ${user.permission}`);
    next(); 
  } catch (e) {
    // On failure
    console.log(`Authentication failed: ${e.message}`)
    res.status(400).send('Invalid token.');
  }
};

export async function loginRoute(req: Request, res: Response) {
  const credentials = req.body;
  try {
    await User.validate(credentials);
  }
  catch (e) {
    res.status(400).send('Invalid credentials');
    return;
  }

  let user;

  try {
    user = await User.findOne({ username: credentials.username });
  }
  catch (e) {
    res.status(500).send('Internal server error');
    return;
  }

  if (!user || !await bcrypt.compare(credentials.password, user.password)) {
    res.status(401).send('Invalid credentials');
    return;
  }

  /* TODO: set JWT_SECRET using .env file */
  const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '2d' })

  const sameSite = process.env.NODE_ENV === 'production' ? 'none' : 'strict';

  const cookieOptions:any = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', 
    sameSite: sameSite,
    expires: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000), 
    // domain:'events-ticketing-system.onrender.com'
  }
  res.cookie('token', token, cookieOptions);

//   /* TODO: set the cookie in the response */
//   res.cookie('token', token, {
//     secure: false, // Set to true in production
//     httpOnly: true,
//     maxAge: 2 * 24 * 60 * 60 * 1000, // 2 days
//     sameSite: 'none', // Less restrictive during development
// });
  
  /* ========== */
  res.status(200).send({token : token , userId: user._id, username: user.username, userPermission: user.permission});

  // res.status(200).send('Logged in');
}

export async function logoutRoute(req: Request, res: Response) {
  const secure = process.env.NODE_ENV === 'production';
  /* TODO: clear the token cookie */
  res.clearCookie('token');
 
  res.status(200).send('Logged out');
  /* ========== */
}

export async function signupRoute(req: Request, res: Response) {
  const user = new User(req.body);
  try {
    const error = await user.validate();
  }
  catch (e) {
    res.status(400).send('Invalid credentials');
    return;
  }
  if (await User.exists({ username: user.username })) {
    res.status(400).send('Username already exists');
    return;
  }

  user.password = await bcrypt.hash(user.password, 10);
  try {
    await user.save();
  }
  catch (e) {
    res.status(500).send('Error creating user');
    return;
  }

  res.status(201).send('User created');
}

export async function userProfileRoute(req: Request, res: Response) {
  const token = req.cookies.token;
  console.log('the token is;', token)
  if (!token) {
    res.status(401).send('Not logged in');
    return;
  }

  let username, user;
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    username = (payload as JwtPayload).username;
    user  = await User.findOne({ username: username });
    if (!user) {
      return res.status(404).send('User not found.');
    }
  }
  catch (e) {
    res.status(401).send('Invalid token');
    return;
  }

  res.status(200).send(user);
}

export async function updateUserPermission(req: Request, res: Response) {
  if (req.user.permission !== 'A') {
    return res.status(403).send('Forbidden: Insufficient permissions.');
  }

  const { userId, newRole } = req.body;
  if (!['A', 'W', 'M'].includes(newRole)) {
    return res.status(400).send('Invalid role specified.');
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send('User not found.');
    }

    user.permission = newRole;
    await user.save();

    res.status(200).send({ userId: user._id, newRole: user.permission, username: user.username });
  } catch (error) {
    console.error('Failed to update user role:', error);
    res.status(500).send('Internal server error.');
  }
}


export async function ensureAdminUserExists() {
  const adminUser = await User.findOne({ username: 'admin' });
  if (!adminUser) {
    console.log('Admin user does not exist. Creating one...');
    const hashedPassword = await bcrypt.hash('admin', 10); 
    const newAdminUser = new User({
      username: 'admin',
      password: hashedPassword,
      permission: 'A',
    });
    await newAdminUser.save();
    console.log('Admin user created.');
  } else {
    console.log('Admin user already exists.');
  }
}

export async function getAllUsers(req: Request, res: Response) {
  if (req.user.permission !== 'A') {
    return res.status(403).send('Forbidden: Insufficient permissions.');
  }

  try {
    let { page, size } = req.query;
    const pageNum = page ? parseInt(page as string, 10) : 1;
    const sizeNum = size ? parseInt(size as string, 10) : 10;
    const skip = (pageNum - 1) * sizeNum;
    const users = await User.find()
                            .skip(skip)
                            .limit(sizeNum)
                            .lean();
    const totalUsers = await User.countDocuments();

    res.json({
      page: pageNum,
      size: sizeNum,
      totalUsers,
      users,
    });
  } catch (error) {
    console.error('Failed to retrieve users:', error);
    res.status(500).send('Internal server error.');
  }
}