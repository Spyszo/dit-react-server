/* eslint-disable no-param-reassign */
/* eslint-disable no-underscore-dangle */
/* eslint-disable no-console */
const express = require('express');
const cors = require('cors');
const passport = require('passport');
const rateLimit = require('express-slow-down');
const cookieParser = require('cookie-parser');
const socketIo = require('socket.io');
const fs = require('fs');
const randtoken = require('rand-token').generator({
  chars: 'a-z',
});

require('dotenv').config();

// set up express
const app = express();

require('./board/socket');

require('./config/database');
require('./models/userModel');
require('./config/passport');

app.use(passport.initialize());
app.use(express.json());
app.use(cookieParser());

const speedLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  delayAfter: 100,
  delayMs: 500,
});

if (!process.env.PRODUCTION) {
  console('SpeedLimiter enabled');
  app.use((req, res, next) => {
    setTimeout(next, 500);
  });
  app.use(speedLimiter);
} else {
  app.use((req, res, next) => {
    setTimeout(next, 50);
  });
  app.use(cors({ origin: 'https://localhost:3000', credentials: true }));
}

// set up routes

app.use('/api/auth', require('./routes/auth.js'));
app.use('/api/account', require('./routes/account.js'));

app.use((err) => {
  if (err) {
    console.log('Wystąpił bląd: ', err);
    return err;
  }
  return 'Some error';
});

const PORT = process.env.PORT || 4000;

const server = app.listen(4000, () => console.log(`Serwer running on port: ${PORT}`));

/// ////////////
// SOCKET.IO //
/// ////////////

const path = require('path');
const jwt = require('jsonwebtoken');

const pathToPubKey = path.join(__dirname, 'id_rsa_pub.pem');
const PUB_KEY = fs.readFileSync(pathToPubKey, 'utf8');
const User = require('mongoose').model('User');

const io = socketIo(server, {
  cors: {
    origin: 'http://localhost:3000',
  },
});

const rooms = {
  example: {
    users: {},
  },
};
const guests = [];

const generateRoom = (id) => {
  let roomId = id;
  if (!roomId) {
    roomId = randtoken.generate(8);
  }
  if (rooms[roomId]) return generateRoom();
  return roomId;
};

const generateGuest = () => {
  let i = 1;
  let guest = `Guest${i}`;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    // eslint-disable-next-line no-loop-func
    if (!guests.find((element) => element === guest)) {
      guests.push(guest);
      return guest;
    }
    i += 1;
    guest = `Guest${i}`;
  }
};

const verifyJWT = async (accessToken) => {
  if (!accessToken || accessToken === 'undefined') return null;
  const jwtPayload = jwt.verify(accessToken, PUB_KEY, ['RS256']);
  const user = await User.findOne({ _id: jwtPayload.sub });
  if (!user) return null;
  return { displayName: user.displayName, id: user._id };
};

io.use(async (socket, next) => {
  if (socket.handshake.query && socket.handshake.query.accessToken) {
    const user = await verifyJWT(socket.handshake.query.accessToken);
    socket.displayName = user.displayName;
  } else {
    socket.displayName = generateGuest();
  }
  next();
})
  .on('connection', async (socket) => {
    const { roomId } = socket.handshake.query;
    if (roomId === 'createRoom') {
      const newRoomId = generateRoom();
      socket.emit('redirectToRoom', newRoomId);
      rooms[newRoomId] = { users: {} };
    } else if (!rooms[roomId]) {
      socket.emit('message', 'Room doesn\'t exists!');
    } else {
      rooms[roomId].users[socket.id] = { id: socket.id, displayName: socket.displayName };
      socket.join(roomId);
      socket.to(roomId).emit('newUser', rooms[roomId].users[socket.id]);
    }

    socket.on('createRoom', () => {
      const newRoomId = generateRoom();
      socket.emit('redirectToRoom', newRoomId);
      rooms[newRoomId] = {};
    });

    socket.on('disconnect', () => {
      const index = guests.indexOf(socket.displayName);
      guests.splice(index, 1);
      if (rooms[roomId]) delete rooms[roomId].users[socket.id];
      socket.to(roomId).emit('userLeft', socket.id);
    });
  });
