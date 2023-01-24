//creating server using express and connecting it to mongoDB database

const express = require("express");
const cors = require("cors");
const { v4 } = require("uuid");
const ObjectId = require("mongodb").ObjectID;
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

//wtf-db is the name of the database stored in mongoDB
const database = "wtf-db";

//connection string to connect to the database
const url =
  "mongodb+srv://wtf-user-db:KJtko33Y1Kc5WDsy@cluster0.nu3rdn2.mongodb.net/?retryWrites=true&w=majority";

const client = new MongoClient(url);
const app = express();
app.use(express.json());
app.use(cors());

let result = null;
let db = null;
let collection = null;

//connecting to database
async function connectDB() {
  try {
    result = await client.connect();

    db = result.db(database);

    collection = db.collection("users");

    console.log("Database Connected ");
  } catch (err) {
    console.log(`DB Error : ${err}`);
  }
}

//initializing the server
app.listen(3001, () => {
  console.log("Server Started");
  connectDB();
});

//middleware to validate register api
const validateRegister = async (req, res, next) => {
  const {
    first_name,
    last_name,
    email,
    mobile,
    password,
    role,
    status,
  } = req.body;

  //validating user details
  let passwRegEx = /^(?=.*\d)(?=.*[A-Z])(?=.*[^a-zA-Z0-9])(?!.*\s).{8,}$/;
  let data = await collection
    .find({
      $or: [{ email: email }, { mobile: mobile }],
    })
    .toArray();
  if (data.length !== 0) {
    res.status(501);
    res.send("Email/Mobile already exists");
  } else if (password.match(passwRegEx) === null) {
    res.status(501);
    res.send(
      "Password should be minimum 8 characters long, and should contain at least one Capital letter and at least one Special Character "
    );
  } else if (
    first_name === "" ||
    last_name === "" ||
    email === "" ||
    mobile === "" ||
    password === "" ||
    role === "" ||
    status === ""
  ) {
    res.status(501);
    res.send("All Fields are required");
  } else if (mobile.length !== 10) {
    res.status(501);
    res.send("Mobile should have only 10 digits");
  } else {
    next();
  }
};

//register api
app.post("/register", validateRegister, async (req, res) => {
  const {
    first_name,
    last_name,
    email,
    mobile,
    password,
    role,
    status,
  } = req.body;

  const hashPassword = await bcrypt.hash(password, 10);

  let insertedDoc = await collection.insertOne({
    uid: v4(),
    first_name: first_name,
    last_name: last_name,
    email: email,
    mobile: mobile,
    password: hashPassword,
    role: role,
    status: status,
  });
  if (insertedDoc.acknowledged === true) {
    res.status(200);
    res.send("Account successfully created");
  } else {
    res.status(501);
    res.send("Error Encountered, Please Try Again");
  }
});

//middleware to validate login api
const validateLogin = async (req, res, next) => {
  const { email, role, password } = req.body;

  const result = await collection.find({ email: email }).toArray();

  const comparePassword = await bcrypt.compare(password, result[0].password);

  //validating email and password
  if (result.length === 0) {
    res.status(501);
    res.send("Email does not exist");
  } else if (result[0].role !== role) {
    res.status(501);
    res.send("Email does not belong to the right user role");
  } else if (comparePassword === false) {
    res.status(501);
    res.send("Password is not correct");
  } else {
    let jwtToken;
    const payload = { email: email, uid: result[0].uid };
    jwtToken = jwt.sign(payload, "secretKey", { expiresIn: "30d" });

    req.result = result;
    req.token = jwtToken;
    next();
  }
};

//login api
app.post("/login", validateLogin, async (req, res) => {
  const { result, token } = req;

  res.send({
    status: 200,
    message: "Logged in successfully",
    data: result,
    token: token,
  });
});

//validating jwt token when user making api to get the details
const validateToken = async (req, res, next) => {
  const authObj = req.headers.authorization;

  if (authObj === undefined) {
    res.status(401);
    res.send("Invalid Token/Expired Token");
  } else {
    let jwtToken;
    jwtToken = authObj.split(" ")[1];

    jwt.verify(jwtToken, "secretKey", (error, payload) => {
      if (error) {
        res.status(401);
        res.send("Invalid Token/Expired Token");
      } else {
        req.uid = payload.uid;
        next();
      }
    });
  }
};

//user details api based on uid
app.get("/getUserDetails", validateToken, async (req, res) => {
  const { uid } = req;
  const userDetails = await collection.findOne({ uid: uid });
  res.send(userDetails);
});

//all user details api based on filter
app.get("/allUsers", async (req, res) => {
  const {
    first_name = "",
    last_name = "",
    email = "",
    mobile = "",
    status = "",
    role = "",
  } = req.query;

  const result = await collection
    .find({
      $and: [
        { email: { $regex: `${email}`, $options: "i" } },
        { first_name: { $regex: `${first_name}`, $options: "i" } },
        { last_name: { $regex: `${last_name}`, $options: "i" } },
        { mobile: { $regex: `${mobile}`, $options: "i" } },
        { status: { $regex: `${status}`, $options: "i" } },
        { role: { $regex: `${role}`, $options: "i" } },
      ],
    })
    .toArray();
  res.send(result);
});
