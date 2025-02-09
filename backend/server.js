const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Configure Multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

// File filter for images only
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Create uploads directory if it doesn't exist
const fs = require('fs');
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

const uri = process.env.MONGODB_URI;
console.log("MongoDB URI is defined:", uri);

const client = new MongoClient(uri);

async function connectDB() {
  try {
    await client.connect();
    console.log("Connected to MongoDB!");
  } catch (error) {
    console.error("Failed to connect to MongoDB", error);
    process.exit(1);
  }
}

connectDB();

const db = client.db('MugoMarbles');
const cakesCollection = db.collection('cakes');
const ordersCollection = db.collection('orders');
const completedOrdersCollection = db.collection('completedOrders');
const cancelledOrdersCollection = db.collection('cancelledOrders');

// Create a new order
app.post('/api/orders', async (req, res) => {
  // Make a shallow copy of the order from the client
  let order = { ...req.body };

  try {
    // If the order includes a buyer name, fetch the corresponding user to get their location
    if (order.name) {
      const user = await db.collection('users').findOne({ username: order.name });
      if (user && user.location) {
         order.location = user.location;  // Attach location (county and workArea)
      }
    }
    order.status = 'pending';
    const result = await ordersCollection.insertOne(order);
    res.status(201).json({ ...order, _id: result.insertedId });
  } catch (error) {
    console.error("Error creating order:", error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// (Other order endpoints remain unchanged)
app.get('/api/orders', async (req, res) => {
  try {
    const orders = await ordersCollection.find().toArray();
    res.json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.patch('/api/orders/:orderId', async (req, res) => {
  const { orderId } = req.params;
  const { status, orders } = req.body;

  try {
    const existingOrder = await ordersCollection.findOne({ _id: new ObjectId(orderId) });
    if (!existingOrder) {
      return res.status(404).json({ error: 'Order not found' });
    }

    await ordersCollection.updateOne(
      { _id: new ObjectId(orderId) },
      { $set: { status, orders, totalCost: req.body.totalCost } }
    );
    
    let updatedOrder;
    if (status === 'completed') {
      await completedOrdersCollection.insertOne({ ...existingOrder, status, orders });
      await ordersCollection.deleteOne({ _id: new ObjectId(orderId) });
      updatedOrder = await completedOrdersCollection.findOne({ _id: new ObjectId(orderId) });
    } else if (status === 'cancelled') {
      await cancelledOrdersCollection.insertOne({ ...existingOrder, status, orders });
      await ordersCollection.deleteOne({ _id: new ObjectId(orderId) });
      updatedOrder = await cancelledOrdersCollection.findOne({ _id: new ObjectId(orderId) });
    } else {
      updatedOrder = await ordersCollection.findOne({ _id: new ObjectId(orderId) });
    }

    res.json(updatedOrder);

  } catch (error) {
    console.error("Error updating order:", error);
    res.status(500).json({ error: 'Failed to update order' });
  }
});

// Create a new cake
app.post('/api/cakes', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image uploaded' });
    }

    const cake = {
      name: req.body.name,
      price: req.body.price,
      image: `/uploads/${req.file.filename}` // Store relative path
    };

    const result = await cakesCollection.insertOne(cake);
    res.status(201).json({ ...cake, _id: result.insertedId });
  } catch (error) {
    console.error("Error creating cake:", error);
    res.status(500).json({ error: 'Failed to create cake' });
  }
});

// Serve static files from /uploads
app.use('/uploads', express.static('uploads'));

app.get('/api/cakes', async (req, res) => {
  try {
    const cakes = await cakesCollection.find().toArray();
    res.json(cakes);
  } catch (error) {
    console.error("Error fetching cakes:", error);
    res.status(500).json({ error: 'Failed to fetch cakes' });
  }
});

app.delete('/api/cakes/:cakeId', async (req, res) => {
  const { cakeId } = req.params;
  try {
    const result = await cakesCollection.deleteOne({ _id: new ObjectId(cakeId) });
    if (result.deletedCount === 1) {
      res.sendStatus(204);
    } else {
      res.status(404).json({ error: 'Cake not found' });
    }
  } catch (error) {
    console.error("Error deleting cake:", error);
    res.status(500).json({ error: 'Failed to delete cake' });
  }
});

app.get('/api/completed-orders', async (req, res) => {
  try {
    const completedOrders = await completedOrdersCollection.find().toArray();
    res.json(completedOrders);
  } catch (error) {
    console.error("Error fetching completed orders:", error);
    res.status(500).json({ error: 'Failed to fetch completed orders' });
  }
});

app.get('/api/cancelled-orders', async (req, res) => {
  try {
    const cancelledOrders = await cancelledOrdersCollection.find().toArray();
    res.json(cancelledOrders);
  } catch (error) {
    console.error("Error fetching cancelled orders:", error);
    res.status(500).json({ error: 'Failed to fetch cancelled orders' });
  }
});

app.delete('/api/orders/:status', async (req, res) => {
  const { status } = req.params;
  
  try {
    let result;
    
    if (status === 'completed') {
      result = await completedOrdersCollection.deleteMany({});
    } else if (status === 'cancelled') {
      result = await cancelledOrdersCollection.deleteMany({});
    } else {
      return res.status(400).json({ error: 'Invalid status' });
    }

    // Instead of sending a 404 if no orders were deleted,
    // we send a 204 (or a 200 with a message) to indicate "nothing to delete"
    res.sendStatus(204);
  } catch (error) {
    console.error("Error deleting orders:", error);
    res.status(500).json({ error: 'Failed to delete orders' });
  }
});


// -------------------
// User Authentication
// -------------------

// Registration endpoint in server.js
// Registration endpoint in server.js
app.post('/api/register', async (req, res) => {
  // Expecting: username, password, county, workArea
  const { username, password, county, workArea } = req.body;

  // Validate county value
  const allowedCounties = ['Nyeri', 'Kirinyaga'];
  if (!allowedCounties.includes(county)) {
    return res.status(400).json({ error: 'Invalid county. Please select either Nyeri or Kirinyaga.' });
  }

  try {
    const existingUser = await db.collection('users').findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    // Public registrations are always "user"
    const newUser = { 
      username, 
      password: hashedPassword, 
      role: 'user',  
      location: { county, workArea }  
    };

    const result = await db.collection('users').insertOne(newUser);
    res.status(201).json({ message: 'User registered successfully', _id: result.insertedId });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ error: 'Failed to register user' });
  }
});


// Login User
// Login User
// Login User
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await db.collection('users').findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ error: 'Incorrect password' });
    }

    // Ensure the role is set (default to 'user' if missing)
    const userRole = user.role || 'user';

    // Include role in both the token payload and the response
    const token = jwt.sign({ userId: user._id, role: userRole }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token, role: userRole });
  } catch (error) {
    console.error("Error logging in user:", error);
    res.status(500).json({ error: 'Failed to login user' });
  }
});



// Middleware to authenticate user for protected routes
function authenticateUser(req, res, next) {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// (If you want to protect all /api/* routes, add the middleware below. 
// Note: Place this line AFTER public endpoints like register and login.)
// app.use('/api/*', authenticateUser);
// -------------------
// Contact Messages
// -------------------

// POST /api/messages - Receive a new contact message
app.post('/api/messages', async (req, res) => {
  const { name, email, message } = req.body;
  
  if (!name || !email || !message) {
    return res.status(400).json({ error: 'Please provide name, email, and message.' });
  }
  
  try {
    const result = await db.collection('messages').insertOne({
      name,
      email,
      message,
      createdAt: new Date()
    });
    
    res.status(201).json({ message: 'Message received successfully.', _id: result.insertedId });
  } catch (error) {
    console.error("Error receiving message:", error);
    res.status(500).json({ error: 'Failed to receive message.' });
  }
});

// GET /api/messages - Retrieve all contact messages
app.get('/api/messages', async (req, res) => {
  try {
    const messages = await db.collection('messages').find().toArray();
    res.json(messages);
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ error: 'Failed to fetch messages.' });
  }
});




const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}`);
});
