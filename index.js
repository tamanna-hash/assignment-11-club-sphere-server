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
const verifyJWT = async (req, res, next) => {
  const token = req?.headers?.authorization?.split(" ")[1];

  if (!token) return res.status(401).send({ message: "Unauthorized Access!" });
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;
    next();
  } catch (err) {
    console.log(err);
    return res.status(401).send({ message: "Unauthorized Access!", err });
  }
};

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
    const eventCollection = db.collection("events");
    const membershipCollection = db.collection("memberships");
    const eventRegisterCollection = db.collection("eventRegisters");
    const paymentCollection = db.collection("payments");
    const userCollection = db.collection("users");
    const managerRequestCollection = db.collection("managerRequests");
    const clubRequestCollection = db.collection("clubRequests");
    // role middlewares
    const verifyADMIN = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await userCollection.findOne({ email });
      if (user?.role !== "admin")
        return res
          .status(403)
          .send({ message: "Admin only Actions!", role: user?.role });

      next();
    };
    const verifyMANAGER = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await userCollection.findOne({ email });
      if (user?.role !== "manager")
        return res
          .status(403)
          .send({ message: "Manager only Actions!", role: user?.role });

      next();
    };
    // club apis
    // get all clubs
    app.get("/clubs", async (req, res) => {
      const query = {};
      const result = await clubCollection.find(query).toArray();
      res.send(result);
    });
    // update club for manager
    app.patch("/clubs/:id", async (req, res) => {
      const { id } = req.params;
      const clubData = req.body;
      const query = { _id: new ObjectId(id) };
      delete clubData._id;
      const updatedData = { $set: clubData };
      const result = await clubCollection.updateOne(query, updatedData);
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
      console.log(result);
      res.send(result);
    });
    // post club
    app.post("/club-requests", verifyJWT, verifyMANAGER, async (req, res) => {
      const clubData = req.body;
      clubData.created_at = new Date();
      clubData.status = "pending";
      const result = await clubRequestCollection.insertOne(clubData);
      res.send(result);
    });
    // post approve club
    app.post("/clubs-approve/:id", verifyJWT, verifyADMIN, async (req, res) => {
      const club = req.body;
      const id = req.params.id;

      delete club._id;
      club.status = "approved";
      // Try both ObjectId and string
      let filter;
      try {
        filter = { _id: new ObjectId(id) };
      } catch {
        filter = { _id: id };
      }

      const insertResult = await clubCollection.insertOne(club);
      const deleteResult = await clubRequestCollection.deleteOne(filter);

      res.send({ inserted: insertResult, deleted: deleteResult });
    });
    // delete club request for admin
    app.delete(
      "/clubs-reject/:id",
      verifyJWT,
      verifyADMIN,
      async (req, res) => {
        const { id } = req.params;
        const filter = { _id: new ObjectId(id) };
        const result = await clubRequestCollection.deleteOne(filter);
        res.send(result);
      }
    );
    // get all club requests for admin
    app.get("/club-requests", verifyJWT, verifyADMIN, async (req, res) => {
      const result = await clubRequestCollection.find().toArray();
      res.send(result);
    });
    // get all club requests for manager by email
    app.get("/clubs-pending", verifyJWT, verifyMANAGER, async (req, res) => {
      const email = req.tokenEmail;
      const result = await clubRequestCollection
        .find({ "manager.email": email })
        .toArray();
      res.send(result);
    });
    // get single club requests for manager by id
    app.get(
      "/clubs-pending/:id",
      verifyJWT,
      verifyMANAGER,
      async (req, res) => {
        const id = req.params.id;
        const email = req.tokenEmail;

        const query = { _id: new ObjectId(id) };
        const result = await clubRequestCollection.findOne(query);

        if (!result) return res.status(404).send("Not found");

        if (result.manager.email !== email) {
          return res.status(401).send("Unauthorized");
        }
        res.send(result);
      }
    );
    app.patch(
      "/clubs-pending/:id",
      verifyJWT,
      verifyMANAGER,
      async (req, res) => {
        const { id } = req.params;
        const clubData = req.body;
        console.log(clubData);
        const query = { _id: new ObjectId(id) };
        delete clubData._id;
        const updatedData = { $set: clubData };
        const result = await clubRequestCollection.updateOne(
          query,
          updatedData
        );
        res.send(result);
      }
    );

    // get all clubs for manager by email
    app.get(
      "/my-inventory/:email",
      verifyJWT,
      verifyMANAGER,
      async (req, res) => {
        const email = req.params.email;
        const result = await clubCollection
          .find({ "manager.email": email })
          .toArray();
        res.send(result);
      }
    );
    // delete single club for manager by id
    app.delete(
      "/clubs-delete/:id",
      verifyJWT,
      verifyMANAGER,
      async (req, res) => {
        try {
          const { id } = req.params;
          const query = { _id: new ObjectId(id) };

          const result = await clubCollection.deleteOne(query);

          if (result.deletedCount === 0) {
            return res.status(404).send({ message: "club not found" });
          }

          res.send({ message: "club deleted successfully", result });
        } catch (error) {
          console.error(error);
          res.status(500).send({ message: "Internal Server Error", error });
        }
      }
    );
    // event api
    app.post("/events", verifyJWT, verifyMANAGER, async (req, res) => {
      const eventData = req.body;
      console.log(eventData);
      eventData.created_at = new Date();
      const result = await eventCollection.insertOne(eventData);
      res.send(result);
    });
    // get all events public
    app.get("/events", async (req, res) => {
      const result = await eventCollection.find().toArray();
      res.send(result);
    });
    // get all events for manager by their email
    app.get("/events-secure", verifyJWT, verifyMANAGER, async (req, res) => {
      const email = req.tokenEmail;
      const query = { "manager.email": email };
      const result = await eventCollection.find(query).toArray();
      res.send(result);
    });
    // update single event for manager
    app.patch("/events/:id", async (req, res) => {
      const { id } = req.params;
      const eventData = req.body;
      const query = { _id: new ObjectId(id) };
      delete eventData._id;
      const updatedData = { $set: eventData };
      const result = await eventCollection.updateOne(query, updatedData);
      res.send(result);
    });

    app.post("/event-registration", async (req, res) => {
      const { eventId, userEmail, clubId, manager } = req.body;
      // check if already joined
      console.log(req.body);
      const existing = await eventRegisterCollection.findOne({
        eventId,
        userEmail,
      });

      if (existing) {
        return res.status(409).send({
          message: "You already joined this event",
          alreadyJoined: true,
        });
      }

      const eventRegisterData = {
        eventId,
        userEmail,
        clubId,
        manager,
        status: "registered",
        registeredAt: new Date(),
      };

      const result = await eventRegisterCollection.insertOne(eventRegisterData);
      res.send(result);
    });
    app.get(
      "/event-registrations",
      verifyJWT,
      verifyMANAGER,
      async (req, res) => {
        const email = req.tokenEmail;
        const query = { "manager.email": email };
        const result = await eventRegisterCollection.find(query).toArray();
        res.send(result);
      }
    );
    app.patch(
      "/event-register-remove/:id",
      verifyJWT,
      verifyMANAGER,
      async (req, res) => {
        const managerEmail = req.tokenEmail;
        const { id } = req.params;

        // find registration
        const registration = await eventRegisterCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!registration) {
          return res.status(404).send({ message: "Registration not found" });
        }
        // if already cancelled
        if (registration.status === "cancelled") {
          return res
            .status(400)
            .send({ message: "Registration Already Cancelled" });
        }
        // check event ownership
        const event = await eventCollection.findOne({
          _id: new ObjectId(registration.eventId),
          "manager.email": managerEmail,
        });

        if (!event) {
          return res.status(403).send({ message: "Not authorized" });
        }

        const result = await eventRegisterCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              status: "cancelled",
              cancelledAt: new Date(),
            },
          }
        );

        res.send(result);
      }
    );

    app.get("/event-registration/status", async (req, res) => {
      const { eventId, email } = req.query;

      const joined = await eventRegisterCollection.findOne({
        eventId,
        userEmail: email,
      });

      res.send({ joined: !!joined });
    });
    // get single club api
    // single club api
    app.get("/events/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await eventCollection.findOne(query);
      res.send(result);
    });
    // stripe checkout session
    app.post("/create-checkout-session", async (req, res) => {
      const paymentInfo = req.body;
      const { paymentId } = paymentInfo;
      const alreadyPaid = await paymentCollection.findOne({ paymentId });
      if (alreadyPaid) {
        return res.send({ message: "Already paid" });
      }
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
    // after payment insert the member in collection
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
    // get all payments for admin
    app.get("/all-payments", verifyJWT, verifyADMIN, async (req, res) => {
      const result = await paymentCollection.find().toArray();
      res.send(result);
    });
    // get payments for manager by email
    app.get("/manager-payments", verifyJWT, verifyMANAGER, async (req, res) => {
      const email = req.tokenEmail;
      const query = { "manager.email": email };
      const result = await paymentCollection.find(query).toArray();
      res.send(result);
    });
    // memberships apis
    //  get all memberships for a customer by email
    app.get("/my-memberships", verifyJWT, async (req, res) => {
      const result = await membershipCollection
        .find({ member: req.tokenEmail })
        .toArray();
      res.send(result);
    });
    // get all memberships for manager by email
    app.get(
      "/manage-memberships",
      verifyJWT,
      verifyMANAGER,
      async (req, res) => {
        const email = req.tokenEmail;
        const result = await membershipCollection
          .find({ "manager.email": email })
          .toArray();
        res.send(result);
      }
    );
    // update membership data after approve
    app.patch(
      "/manage-membership/:id",
      verifyJWT,
      verifyMANAGER,
      async (req, res) => {
        const { id } = req.params;
        const query = { _id: new ObjectId(id) };
        const updatedData = {
          $set: {
            status: "joined",
            joined_at: new Date(),
          },
        };
        const result = await membershipCollection.updateOne(query, updatedData);
        res.send(result);
      }
    );
    // delete membership data if reject
    app.delete(
      "/membership-reject/:id",
      verifyJWT,
      verifyMANAGER,
      async (req, res) => {
        try {
          const { id } = req.params;
          const query = { _id: new ObjectId(id) };

          const result = await membershipCollection.deleteOne(query);

          if (result.deletedCount === 0) {
            return res.status(404).send({ message: "Membership not found" });
          }

          res.send({ message: "Membership deleted successfully", result });
        } catch (error) {
          console.error(error);
          res.status(500).send({ message: "Internal Server Error", error });
        }
      }
    );
    // user apis
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
    // get all users for admin
    app.get("/users", verifyJWT, verifyADMIN, async (req, res) => {
      const adminEmail = req.tokenEmail;
      console.log(adminEmail);
      const result = await userCollection
        .find({ email: { $ne: adminEmail } })
        .toArray();
      res.send(result);
    });
    // get a user's role
    app.get("/user/role", verifyJWT, async (req, res) => {
      //  console.log(req.tokenEmail)
      const result = await userCollection.findOne({ email: req.tokenEmail });
      res.send({ role: result?.role });
    });

    // save become-manager request
    app.post("/become-manager", verifyJWT, async (req, res) => {
      const email = req.tokenEmail;
      const alreadyExists = await managerRequestCollection.findOne({ email });
      if (alreadyExists)
        return res.status(409).send({
          message: "Already requested,please wait for admin approval.",
        });
      const result = managerRequestCollection.insertOne({ email });
      res.send(result);
    });
    // get all manager requests for admin
    app.get("/manager-requests", verifyJWT, verifyADMIN, async (req, res) => {
      const result = await managerRequestCollection.find().toArray();
      res.send(result);
    });

    // update a user's role
    app.patch("/update-role", verifyJWT, verifyADMIN, async (req, res) => {
      const { email, role } = req.body;
      const result = await userCollection.updateOne(
        { email },
        { $set: { role } }
      );
      await managerRequestCollection.deleteOne({ email });

      res.send(result);
    });
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
