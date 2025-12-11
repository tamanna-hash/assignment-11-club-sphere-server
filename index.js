require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const port = process.env.PORT || 3000;
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf-8"
);
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
// middleware
app.use(
  cors({
    origin: [process.env.CLIENT_DOMAIN],
    credentials: true,
    optionSuccessStatus: 200,
  })
);
app.use(express.json());

// jwt middlewares
// const verifyJWT = async (req, res, next) => {
//   const token = req?.headers?.authorization?.split(' ')[1]
//   console.log(token)
//   if (!token) return res.status(401).send({ message: 'Unauthorized Access!' })
//   try {
//     const decoded = await admin.auth().verifyIdToken(token)
//     req.tokenEmail = decoded.email
//     console.log(decoded)
//     next()
//   } catch (err) {
//     console.log(err)
//     return res.status(401).send({ message: 'Unauthorized Access!', err })
//   }
// }

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  try {
    const db = client.db("clubSphereDB");
    const clubCollection = db.collection("clubs");
    const membershipCollection = db.collection("memberships");
    const paymentCollection = db.collection("payments");
    const userCollection = db.collection("users");
    // club apis
    // get all clubs
    app.get("/clubs", async (req, res) => {
      const query = {};
      const result = await clubCollection.find(query).toArray();
      res.send(result);
    });
    // single club api
    app.get("/clubs/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      //   if (id) {
      //     query.id = { _id: new ObjectId(id) };
      //   }
      const result = await clubCollection.findOne(query);
      res.send(result);
    });
    // post club
    app.post("/clubs", async (req, res) => {
      const clubData = req.body;
      clubData.created_at = new Date();
      clubData.status = "pending";
      const result = await clubCollection.insertOne(clubData);
      res.send(result);
    });
    // stripe checkout session
    app.post("/create-checkout-session", async (req, res) => {
      const paymentInfo = req.body;
      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: paymentInfo?.clubName,
                description: paymentInfo?.description,
                images: [paymentInfo.coverImage],
              },
              unit_amount: paymentInfo?.membershipFee * 100,
            },
            quantity: 1,
          },
        ],
        customer_email: paymentInfo?.member?.email,
        mode: "payment",
        metadata: {
          clubId: paymentInfo?.clubId,
          member: paymentInfo?.member.email,
        },
        success_url: `${process.env.CLIENT_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.CLIENT_DOMAIN}/clubs/${paymentInfo?.clubId}`,
      });
      res.send({ url: session.url });
    });
    app.post("/payment-success", async (req, res) => {
      const { sessionId } = req.body;
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      const club = await clubCollection.findOne({
        _id: new ObjectId(session.metadata.clubId),
      });
      const membership = await membershipCollection.findOne({
        paymentId: session.payment_intent,
      });

      if (session.status === "complete" && club && !membership) {
        // save membership data in db
        const membershipInfo = {
          clubId: session.metadata.clubId,
          paymentId: session.payment_intent,
          member: session.metadata.member,
          status: "pending",
          manager: club.manager,
          name: club.clubName,
          category: club.category,
          quantity: 1,
          fee: session.amount_total / 100,
          image: club?.coverImage,
        };
        const paymentInfo = {
          clubId: session.metadata.clubId,
          transactionId: session.payment_intent,
          userEmail: session.metadata.member,
          status: "pending",
          manager: club.manager,
          name: club.clubName,
          category: club.category,
          amount: session.amount_total / 100,
          createdAt: new Date(),
        };
        const membershipResult = await membershipCollection.insertOne(
          membershipInfo
        );
        const paymentResult = await paymentCollection.insertOne(paymentInfo);
        return res.send({
          transactionId: session.payment_intent,
          membershipId: result.insertedId,
        });
      }
      return res.send({
        transactionId: session.payment_intent,
        membershipId: membership._id,
      });
    });

    //  get all memberships for a customer by email
    app.get("/my-memberships/:email", async (req, res) => {
      const email = req.params.email;
      const result = await membershipCollection
        .find({ member: email })
        .toArray();
      res.send(result);
    });
    app.get("/manage-memberships/:email", async (req, res) => {
      const email = req.params.email;
      const result = await membershipCollection
        .find({ "manager.email": email })
        .toArray();
      res.send(result);
    });
    // get all clubs for manager by email
    app.get("/my-inventory/:email", async (req, res) => {
      const email = req.params.email;
      const result = await clubCollection
        .find({ "manager.email": email })
        .toArray();
      res.send(result);
    });
    // save or update a user in db
    app.post("/user", async (req, res) => {
      const userData = req.body;
      userData.created_at = new Date().toISOString();
      userData.last_loggedIn = new Date().toISOString();
      userData.role = "member";

      const query = {
        email: userData.email,
      };

      const alreadyExists = await userCollection.findOne(query);
      console.log("User Already Exists---> ", !!alreadyExists);

      if (alreadyExists) {
        console.log("Updating user info......");
        const result = await userCollection.updateOne(query, {
          $set: {
            last_loggedIn: new Date().toISOString(),
          },
        });
        return res.send(result);
      }

      console.log("Saving new user info......");
      const result = await userCollection.insertOne(userData);
      res.send(result);
    });
    app.get('/users',async(req,res)=>{
      const result = await userCollection.find().toArray()
      res.send (result)
    })
  // get a user's role
    app.get('/user/role/:email', async (req, res) => {
      const result = await userCollection.findOne({ email: req.params.email})
      res.send({ role: result?.role })
    })



    
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello from Server..");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
