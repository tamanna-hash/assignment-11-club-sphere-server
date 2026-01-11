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
    origin: [
      process.env.CLIENT_DOMAIN,
      process.env.OTHER_CLIENT_DOMAIN,
      process.env.LOCAL_HOST,
    ],
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
    const wishlistCollection = db.collection("wishlists");
    const notificationCollection = db.collection("notifications");
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
    const blockDemoAdmin = (req, res, next) => {
      if (req.tokenEmail === "admin@gmail.com") {
        return res.status(403).send({
          message: "Demo mode: destructive actions are disabled",
        });
      }
      next();
    };
    const blockDemoManager = (req, res, next) => {
      // email comes from verified JWT
      if (req.tokenEmail === "jhankar@gmail.com") {
        return res.status(403).send({
          message: "Demo manager: destructive actions are disabled",
        });
      }
      next();
    };

    // club apis
    // get all clubs
    app.get("/clubs", async (req, res) => {
      try {
        const { search = "", category, sort, page = 1, limit = 12 } = req.query;

        const query = {};

        // 🔍 Search
        if (search) {
          query.clubName = { $regex: search, $options: "i" };
        }

        // 🏷️ Filter
        if (category && category !== "all") {
          query.category = category;
        }

        // 🔃 Sorting
        let sortOption = {};
        switch (sort) {
          case "newest":
            sortOption = { created_at: -1 };
            break;
          case "oldest":
            sortOption = { created_at: 1 };
            break;
          case "highest-fee":
            sortOption = { membershipFee: -1 };
            break;
          case "lowest-fee":
            sortOption = { membershipFee: 1 };
            break;
          default:
            sortOption = { created_at: -1 };
        }

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await clubCollection.countDocuments(query);

        const result = await clubCollection
          .find(query)
          .sort(sortOption)
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        res.send({
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          totalPages: Math.ceil(total / limit),
          data: result,
        });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to fetch clubs" });
      }
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
    app.post("/clubs-approve/:id", verifyJWT, verifyADMIN,blockDemoAdmin, async (req, res) => {
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
      blockDemoAdmin,
      async (req, res) => {
        const { id } = req.params;
        const filter = { _id: new ObjectId(id) };
        const result = await clubRequestCollection.deleteOne(filter);
        res.send(result);
      }
    );
    app.delete(
      "/club-delete/pending/:id",
      verifyJWT,
      verifyMANAGER,
      blockDemoManager,
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
    app.get("/my-joined-clubs", verifyJWT, async (req, res) => {
      try {
        const userEmail = req.tokenEmail;

        const joinedClubs = await membershipCollection
          .find({
            member: userEmail,
            status: "joined",
          })
          .toArray();

        res.send(joinedClubs);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to fetch joined clubs" });
      }
    });
    app.patch(
      "/clubs-pending/:id",
      verifyJWT,
      verifyMANAGER,
      async (req, res) => {
        const { id } = req.params;
        const clubData = req.body;
        // console.log(clubData);
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
      blockDemoManager,
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
    // get all club for admin dashboard statistics
    app.get("/admin/clubs", verifyJWT, verifyADMIN, async (req, res) => {
      const result = await clubCollection
        .aggregate([
          // 🔹 Convert club _id to string for matching
          {
            $addFields: {
              clubIdStr: { $toString: "$_id" },
            },
          },

          // 🔹 Lookup memberships (clubId is string)
          {
            $lookup: {
              from: "memberships",
              localField: "clubIdStr",
              foreignField: "clubId",
              as: "members",
            },
          },

          // 🔹 Lookup events (clubId is string)
          {
            $lookup: {
              from: "events",
              localField: "clubIdStr",
              foreignField: "clubId",
              as: "events",
            },
          },

          // 🔹 Count
          {
            $addFields: {
              membersCount: { $size: "$members" },
              eventsCount: { $size: "$events" },
            },
          },

          // 🔹 Optional: remove temp field
          {
            $project: {
              clubIdStr: 0,
            },
          },
        ])
        .toArray();

      res.send(result);
    });
    // event api
    app.post("/events", verifyJWT, verifyMANAGER, async (req, res) => {
      const eventData = req.body;
      // console.log(eventData);
      eventData.created_at = new Date();
      const result = await eventCollection.insertOne(eventData);

      // Create notifications for all club members when a new event is created
      if (result.insertedId) {
        try {
          const clubMembers = await membershipCollection
            .find({
              clubId: eventData.clubId,
              status: "joined",
            })
            .toArray();

          const notifications = clubMembers.map((member) => ({
            userId: member.member,
            type: "event_created",
            title: "New Event Created!",
            message: `A new event "${eventData.title}" has been created in ${eventData.clubName}. Check it out!`,
            clubName: eventData.clubName,
            clubId: eventData.clubId,
            eventId: result.insertedId.toString(),
            eventTitle: eventData.title,
            isRead: false,
            createdAt: new Date(),
          }));

          if (notifications.length > 0) {
            await notificationCollection.insertMany(notifications);
          }
        } catch (error) {
          console.error("Error creating event notifications:", error);
        }
      }

      res.send(result);
    });
    // get all events public
    app.get("/events", async (req, res) => {
      try {
        const { search = "", clubId, isPaid, sort } = req.query;

        const query = {};

        // 🔗 Filter by club
        if (clubId) {
          query.clubId = clubId;
        }

        // 🔍 Search by title
        if (search) {
          query.title = { $regex: search, $options: "i" };
        }

        // 💰 Filter paid/free
        if (isPaid === "true") query.isPaid = true;
        if (isPaid === "false") query.isPaid = false;

        // 🔃 Sorting
        let sortOption = {};
        switch (sort) {
          case "newest":
            sortOption = { created_at: -1 };
            break;
          case "oldest":
            sortOption = { created_at: 1 };
            break;
          case "event-soon":
            sortOption = { eventDate: 1 };
            break;
          case "event-late":
            sortOption = { eventDate: -1 };
            break;
          default:
            sortOption = { created_at: -1 };
        }

        const events = await eventCollection
          .find(query)
          .sort(sortOption)
          .toArray();

        res.send(events);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to fetch events" });
      }
    });

    // get events for members they are joined
    app.get("/my-joined-events", verifyJWT, async (req, res) => {
      const userEmail = req.tokenEmail;
      const registrations = await eventRegisterCollection
        .find({ userEmail, status: "registered" })
        .toArray();
      const eventIds = registrations.map((r) => new ObjectId(r.eventId));
      const events = await eventCollection
        .find({ _id: { $in: eventIds } })
        .toArray();
      const joinedEvents = events.map((event) => {
        const registration = registrations.find(
          (r) => r.eventId === event._id.toString()
        );
        return {
          ...event,
          status: registration.status,
          registeredAt: registration.registeredAt,
          cancelledAt: registration.cancelledAt || null,
        };
      });

      res.send(joinedEvents);
    });
    // get all events for manager by their email
    app.get("/events-secure", verifyJWT, verifyMANAGER, async (req, res) => {
      const email = req.tokenEmail;
      const query = { "manager.email": email };
      const result = await eventCollection.find(query).toArray();
      res.send(result);
    });
    // update single event for manager
    app.patch("/events/:id", verifyJWT, verifyMANAGER, async (req, res) => {
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
      // console.log(req.body);
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

      // Create notification for manager when someone registers for their event
      if (result.insertedId) {
        try {
          const event = await eventCollection.findOne({
            _id: new ObjectId(eventId),
          });
          if (event && manager?.email) {
            const notification = {
              userId: manager.email,
              type: "event_registration",
              title: "New Event Registration!",
              message: `${userEmail} has registered for your event "${event.title}".`,
              clubName: event.clubName,
              clubId: clubId,
              eventId: eventId,
              eventTitle: event.title,
              memberEmail: userEmail,
              isRead: false,
              createdAt: new Date(),
            };

            await notificationCollection.insertOne(notification);
          }
        } catch (error) {
          console.error("Error creating registration notification:", error);
        }
      }

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
        // console.log(result);
        res.send(result);
      }
    );
    app.patch(
      "/event-register-remove/:id",
      verifyJWT,
      verifyMANAGER,
      blockDemoManager,
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
      const { clubId, memberEmail, transactionId } = paymentInfo;

      // 1. check existing payment FIRST
      const existingPayment = await paymentCollection.findOne({
        clubId,
        transactionId: transactionId,
      });

      if (existingPayment) {
        return res.status(400).send({
          message: "You have already paid for this club",
          transactionId: existingPayment.transactionId,
        });
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
      const transactionId = session.payment_intent;
      const query = { transactionId: transactionId };
      const paymentExist = await paymentCollection.findOne(query);
      if (paymentExist) {
        return res.send({
          message: "already exist",
          trackingId: paymentExist.trackingId,
          transactionId,
        });
      }
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
          status: "paid",
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

        // Create notifications for payment received
        try {
          // Notification for manager about payment received
          const managerNotification = {
            userId: club.manager.email,
            type: "payment_received",
            title: "Payment Received!",
            message: `You received a payment of $${
              session.amount_total / 100
            } for ${club.clubName} membership from ${session.metadata.member}.`,
            clubName: club.clubName,
            clubId: session.metadata.clubId,
            amount: session.amount_total / 100,
            memberEmail: session.metadata.member,
            isRead: false,
            createdAt: new Date(),
          };

          // Notification for member about membership request
          const memberNotification = {
            userId: session.metadata.member,
            type: "membership_request",
            title: "Membership Request Submitted!",
            message: `Your membership request for ${club.clubName} has been submitted and payment received. Waiting for manager approval.`,
            clubName: club.clubName,
            clubId: session.metadata.clubId,
            amount: session.amount_total / 100,
            isRead: false,
            createdAt: new Date(),
          };

          await notificationCollection.insertMany([
            managerNotification,
            memberNotification,
          ]);
        } catch (error) {
          console.error("Error creating payment notifications:", error);
        }

        return res.send({
          transactionId: session.payment_intent,
          membershipId: membershipResult.insertedId,
        });
      }
      return res.send({
        transactionId: session.payment_intent,
        membershipId: membership._id,
      });
    });
    // post for free membership
    app.post("/membership-free", async (req, res) => {
      const membershipInfo = req.body;
      const result = await membershipCollection.insertOne(membershipInfo);

      // Create notification for manager about new free membership request
      if (result.insertedId && membershipInfo.manager?.email) {
        try {
          const notification = {
            userId: membershipInfo.manager.email,
            type: "membership_request",
            title: "New Membership Request!",
            message: `${membershipInfo.member} has requested to join ${membershipInfo.name}. Please review and approve.`,
            clubName: membershipInfo.name,
            clubId: membershipInfo.clubId,
            memberEmail: membershipInfo.member,
            isRead: false,
            createdAt: new Date(),
          };

          await notificationCollection.insertOne(notification);
        } catch (error) {
          console.error(
            "Error creating membership request notification:",
            error
          );
        }
      }

      res.send(result);
    });
    // get all payments for admin
    app.get("/all-payments", verifyJWT, verifyADMIN, async (req, res) => {
      const result = await paymentCollection.find().toArray();
      res.send(result);
    });
    // get payments for member by email
    app.get("/my-payments", verifyJWT, async (req, res) => {
      const email = req.tokenEmail;
      const result = await paymentCollection
        .find({ userEmail: email })
        .toArray();
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
      const { clubId } = req.query;

      const query = {
        member: req.tokenEmail,
        ...(clubId && { clubId }),
      };

      const result = await membershipCollection.find(query).toArray();
      res.send(result);
    });

    app.get(
      "/manage-memberships",
      verifyJWT,
      verifyMANAGER,
      async (req, res) => {
        const email = req.tokenEmail;
        const query = { "manager.email": email };

        if (req.query.status) {
          const statuses = req.query.status.split(",");
          query.status = { $in: statuses };
        }

        const result = await membershipCollection
          .find(query)
          .sort({
            joined_at: 1,
          })
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

        // Get membership details before updating
        const membership = await membershipCollection.findOne(query);

        const updatedData = {
          $set: {
            status: "joined",
            joined_at: new Date(),
          },
        };

        const result = await membershipCollection.updateOne(query, updatedData);

        // Create notification for the member
        if (result.modifiedCount > 0 && membership) {
          const notification = {
            userId: membership.member,
            type: "membership_approved",
            title: "Membership Approved!",
            message: `Your membership to ${membership.name} has been approved. Welcome to the club!`,
            clubName: membership.name,
            clubId: membership.clubId,
            isRead: false,
            createdAt: new Date(),
          };

          await notificationCollection.insertOne(notification);
        }

        res.send(result);
      }
    );
    app.patch(
      "/memberships/:membershipId/expire",
      verifyJWT,
      verifyMANAGER,
      async (req, res) => {
        try {
          const id = req.params.membershipId;
          // console.log(id);
          // if (!ObjectId.isValid(id)) {
          //   return res.status(400).send({ error: "Invalid membership ID" });
          // }

          const result = await membershipCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status: "expired" } }
          );

          if (result.modifiedCount === 1) {
            res.send({ success: true, modifiedCount: 1 });
          } else {
            res.status(404).send({ error: "Membership not found" });
          }
        } catch (err) {
          console.error("Error expiring membership:", err);
          res.status(500).send({ error: "Internal Server Error" });
        }
      }
    );

    // delete membership data if reject
    app.delete(
      "/membership-reject/:id",
      verifyJWT,
      verifyMANAGER,
      blockDemoManager,
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
      // console.log("User Already Exists---> ", !!alreadyExists);

      if (alreadyExists) {
        // console.log("Updating user info......");
        const result = await userCollection.updateOne(query, {
          $set: {
            last_loggedIn: new Date().toISOString(),
          },
        });
        return res.send(result);
      }

      // console.log("Saving new user info......");
      const result = await userCollection.insertOne(userData);
      res.send(result);
    });
    // get all users for admin
    app.get("/users", verifyJWT, verifyADMIN, async (req, res) => {
      const adminEmail = req.tokenEmail;
      // console.log(adminEmail);
      const result = await userCollection
        .find({ email: { $ne: adminEmail } })
        .toArray();
      res.send(result);
    });
    // get a user's role
    app.get("/user/role", verifyJWT, async (req, res) => {
      // console.log(req.tokenEmail);
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
    app.patch(
      "/update-role",
      verifyJWT,
      verifyADMIN,
      blockDemoAdmin,
      async (req, res) => {
        const { email, role } = req.body;
        const result = await userCollection.updateOne(
          { email },
          { $set: { role } }
        );
        await managerRequestCollection.deleteOne({ email });

        res.send(result);
      }
    );
    app.get("/admin-summary", async (req, res) => {
      try {
        const db = client.db("clubSphereDB");

        // Total users
        const totalUsers = await db.collection("users").countDocuments();

        // Total clubs
        const pendingClubs = await db
          .collection("clubRequests")
          .countDocuments({ status: "pending" });

        const approvedClubs = await db
          .collection("clubs")
          .countDocuments({ status: "approved" });

        const clubsSummary = {
          pending: pendingClubs,
          approved: approvedClubs,
        };
        // Total memberships
        const totalMemberships = await db
          .collection("memberships")
          .countDocuments();

        // Total events
        const totalEvents = await db.collection("events").countDocuments();

        // Total payments amount
        const paymentsAgg = await db
          .collection("payments")
          .aggregate([
            { $group: { _id: null, totalAmount: { $sum: "$amount" } } },
          ])
          .toArray();
        const totalPayments = paymentsAgg[0]?.totalAmount || 0;

        // Memberships per club (for chart)
        const membershipsPerClub = await db
          .collection("memberships")
          .aggregate([
            {
              $addFields: { clubObjId: { $toObjectId: "$clubId" } }, // convert string to ObjectId
            },
            {
              $group: {
                _id: "$clubObjId",
                totalMembers: { $sum: 1 },
              },
            },
            {
              $lookup: {
                from: "clubs",
                localField: "_id",
                foreignField: "_id",
                as: "club",
              },
            },
            { $unwind: "$club" },
            { $project: { clubName: "$club.clubName", totalMembers: 1 } },
          ])
          .toArray();
        res.json({
          totalUsers,
          clubsSummary,
          totalMemberships,
          totalEvents,
          totalPayments,
          membershipsPerClub,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });
    app.get("/manager-overview/:email", async (req, res) => {
      try {
        const db = client.db("clubSphereDB");
        const managerEmail = req.params.email;

        // 1️⃣ Number of clubs managed
        const numClubs = await db.collection("clubs").countDocuments({
          "manager.email": managerEmail,
        });

        // 2️⃣ Total members in their clubs (only joined status)
        const memberships = await db
          .collection("memberships")
          .aggregate([
            {
              $addFields: {
                clubObjId: {
                  $cond: [
                    { $eq: [{ $type: "$clubId" }, "string"] },
                    { $toObjectId: "$clubId" },
                    "$clubId",
                  ],
                },
              },
            },
            {
              $lookup: {
                from: "clubs",
                localField: "clubObjId",
                foreignField: "_id",
                as: "club",
              },
            },
            { $unwind: "$club" },
            {
              $match: {
                "club.manager.email": managerEmail,
                status: "joined", // Only count active members
              },
            },
            { $count: "totalMembers" },
          ])
          .toArray();

        const totalMembers = memberships[0]?.totalMembers || 0;

        // 3️⃣ Total events created
        const totalEvents = await db.collection("events").countDocuments({
          "manager.email": managerEmail,
        });

        // 4️⃣ Total payments received for their clubs
        const paymentsAgg = await db
          .collection("payments")
          .aggregate([
            {
              $match: {
                "manager.email": managerEmail,
                status: "paid", // Only count successful payments
              },
            },
            {
              $group: {
                _id: null,
                totalAmount: { $sum: "$amount" },
              },
            },
          ])
          .toArray();
        const totalPayments = paymentsAgg[0]?.totalAmount || 0;

        // 5️⃣ Additional metrics for better insights
        const pendingMemberships = await db
          .collection("memberships")
          .countDocuments({
            "manager.email": managerEmail,
            status: "pending",
          });

        const upcomingEvents = await db.collection("events").countDocuments({
          "manager.email": managerEmail,
          eventDate: { $gte: new Date() },
        });

        res.json({
          numClubs,
          totalMembers,
          totalEvents,
          totalPayments,
          pendingMemberships,
          upcomingEvents,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });
    // GET members per club for a manager
    app.get("/manager-members-per-club/:email", async (req, res) => {
      try {
        const db = client.db("clubSphereDB");
        const managerEmail = req.params.email;

        const clubs = await db
          .collection("clubs")
          .find({ "manager.email": managerEmail })
          .toArray();

        const membersPerClub = await Promise.all(
          clubs.map(async (club) => {
            const memberCount = await db
              .collection("memberships")
              .countDocuments({
                clubId: club._id.toString(),
                status: "joined", // Only count active members
              });

            return {
              label: club.clubName || club.name, // Handle both field names
              value: memberCount,
              clubId: club._id.toString(),
              category: club.category,
            };
          })
        );

        // Filter out clubs with 0 members for cleaner visualization
        const filteredData = membersPerClub.filter((club) => club.value > 0);

        res.json(filteredData);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    // GET clubs vs events for manager (for bar chart)
    app.get("/manager-chart/:email", async (req, res) => {
      try {
        const db = client.db("clubSphereDB");
        const managerEmail = req.params.email;

        // Count clubs managed
        const numClubs = await db.collection("clubs").countDocuments({
          "manager.email": managerEmail,
        });

        // Count events created
        const numEvents = await db.collection("events").countDocuments({
          "manager.email": managerEmail,
        });

        // Count active memberships
        const activeMemberships = await db
          .collection("memberships")
          .countDocuments({
            "manager.email": managerEmail,
            status: "joined",
          });

        // Count total revenue
        const revenueAgg = await db
          .collection("payments")
          .aggregate([
            { $match: { "manager.email": managerEmail, status: "paid" } },
            { $group: { _id: null, total: { $sum: "$amount" } } },
          ])
          .toArray();
        const totalRevenue = revenueAgg[0]?.total || 0;

        // Format for chart with more meaningful data
        const chartData = [
          { label: "Clubs", value: numClubs, color: "#8b5cf6" },
          { label: "Events", value: numEvents, color: "#06b6d4" },
          { label: "Members", value: activeMemberships, color: "#10b981" },
          {
            label: "Revenue ($)",
            value: Math.round(totalRevenue),
            color: "#f59e0b",
          },
        ];

        res.json(chartData);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    // GET manager growth stats (Line Chart)
    app.get("/manager-growth/:email", async (req, res) => {
      try {
        const db = client.db("clubSphereDB");
        const managerEmail = req.params.email;

        const now = new Date();
        const startDate = new Date();
        startDate.setMonth(now.getMonth() - 5);
        startDate.setHours(0, 0, 0, 0);

        const monthNames = [
          "Jan",
          "Feb",
          "Mar",
          "Apr",
          "May",
          "Jun",
          "Jul",
          "Aug",
          "Sep",
          "Oct",
          "Nov",
          "Dec",
        ];

        // MEMBERS (monthly) - use joined_at field if available, otherwise createdAt
        const membersAgg = await db
          .collection("memberships")
          .aggregate([
            {
              $match: {
                "manager.email": managerEmail,
                status: "joined",
                $or: [
                  { joined_at: { $gte: startDate } },
                  { createdAt: { $gte: startDate } },
                ],
              },
            },
            {
              $addFields: {
                dateField: {
                  $ifNull: ["$joined_at", "$createdAt"],
                },
              },
            },
            {
              $group: {
                _id: {
                  year: { $year: "$dateField" },
                  month: { $month: "$dateField" },
                },
                count: { $sum: 1 },
              },
            },
          ])
          .toArray();

        // EVENTS (monthly)
        const eventsAgg = await db
          .collection("events")
          .aggregate([
            {
              $match: {
                "manager.email": managerEmail,
                created_at: { $gte: startDate },
              },
            },
            {
              $group: {
                _id: {
                  year: { $year: "$created_at" },
                  month: { $month: "$created_at" },
                },
                count: { $sum: 1 },
              },
            },
          ])
          .toArray();

        let cumulativeMembers = 0;
        let cumulativeEvents = 0;

        const growthData = Array.from({ length: 6 }).map((_, index) => {
          const date = new Date();
          date.setMonth(now.getMonth() - (5 - index));

          const year = date.getFullYear();
          const month = date.getMonth() + 1;

          const membersThisMonth =
            membersAgg.find((m) => m._id.year === year && m._id.month === month)
              ?.count || 0;

          const eventsThisMonth =
            eventsAgg.find((e) => e._id.year === year && e._id.month === month)
              ?.count || 0;

          cumulativeMembers += membersThisMonth;
          cumulativeEvents += eventsThisMonth;

          return {
            label: monthNames[date.getMonth()],
            members: membersThisMonth,
            events: eventsThisMonth,
            totalMembers: cumulativeMembers,
            totalEvents: cumulativeEvents,
          };
        });

        // Growth comparison (last vs previous)
        const last = growthData[growthData.length - 1];
        const prev = growthData[growthData.length - 2] || last;

        const memberGrowthRate =
          prev.members === 0
            ? last.members > 0
              ? 100
              : 0
            : (((last.members - prev.members) / prev.members) * 100).toFixed(1);

        const eventGrowthRate =
          prev.events === 0
            ? last.events > 0
              ? 100
              : 0
            : (((last.events - prev.events) / prev.events) * 100).toFixed(1);

        res.json({
          growthData,
          insights: {
            memberGrowthRate: Number(memberGrowthRate),
            eventGrowthRate: Number(eventGrowthRate),
          },
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    // NEW: GET member demographics for manager
    app.get("/manager-demographics/:email", async (req, res) => {
      try {
        const db = client.db("clubSphereDB");
        const managerEmail = req.params.email;

        // Get member demographics by club category
        const demographics = await db
          .collection("memberships")
          .aggregate([
            {
              $addFields: {
                clubObjId: {
                  $cond: [
                    { $eq: [{ $type: "$clubId" }, "string"] },
                    { $toObjectId: "$clubId" },
                    "$clubId",
                  ],
                },
              },
            },
            {
              $lookup: {
                from: "clubs",
                localField: "clubObjId",
                foreignField: "_id",
                as: "club",
              },
            },
            { $unwind: "$club" },
            {
              $match: {
                "club.manager.email": managerEmail,
                status: "joined",
              },
            },
            {
              $group: {
                _id: "$club.category",
                count: { $sum: 1 },
              },
            },
            {
              $project: {
                category: "$_id",
                count: 1,
                _id: 0,
              },
            },
          ])
          .toArray();

        res.json(demographics);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    // NEW: GET recent activity for manager
    app.get("/manager-recent-activity/:email", async (req, res) => {
      try {
        const db = client.db("clubSphereDB");
        const managerEmail = req.params.email;

        // Get recent memberships
        const recentMemberships = await db
          .collection("memberships")
          .aggregate([
            {
              $addFields: {
                clubObjId: {
                  $cond: [
                    { $eq: [{ $type: "$clubId" }, "string"] },
                    { $toObjectId: "$clubId" },
                    "$clubId",
                  ],
                },
              },
            },
            {
              $lookup: {
                from: "clubs",
                localField: "clubObjId",
                foreignField: "_id",
                as: "club",
              },
            },
            { $unwind: "$club" },
            {
              $match: {
                "club.manager.email": managerEmail,
              },
            },
            {
              $sort: { joined_at: -1, createdAt: -1 },
            },
            {
              $limit: 10,
            },
            {
              $project: {
                member: 1,
                status: 1,
                clubName: "$club.clubName",
                joinedAt: { $ifNull: ["$joined_at", "$createdAt"] },
                fee: 1,
              },
            },
          ])
          .toArray();

        // Get recent events
        const recentEvents = await db
          .collection("events")
          .find({
            "manager.email": managerEmail,
          })
          .sort({ created_at: -1 })
          .limit(5)
          .toArray();

        res.json({
          recentMemberships,
          recentEvents,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    app.get("/member-overview/:email", async (req, res) => {
      try {
        const db = client.db("clubSphereDB");
        const memberEmail = req.params.email;

        // Total clubs joined
        const totalClubsJoined = await db
          .collection("memberships")
          .countDocuments({
            member: memberEmail,
            status: "joined", // or include pending if needed
          });

        // Total events registered
        const totalEventsRegistered = await db
          .collection("eventRegisters")
          .countDocuments({
            userEmail: memberEmail, // assuming events have an attendees array
          });

        // Upcoming events from their clubs
        const upcomingEvents = await db
          .collection("events")
          .aggregate([
            {
              $lookup: {
                from: "memberships",
                let: { eventClubId: { $toObjectId: "$clubId" } },
                pipeline: [
                  {
                    $match: {
                      $expr: {
                        $eq: [{ $toObjectId: "$clubId" }, "$$eventClubId"],
                      },
                      member: memberEmail,
                    },
                  },
                ],
                as: "memberJoined",
              },
            },
            { $match: { "memberJoined.0": { $exists: true } } }, // only events where member joined
            { $sort: { eventDate: 1 } },
            {
              $project: {
                title: 1,
                eventDate: 1,
                eventLocation: 1,
                bannerImage: 1,
              },
            },
          ])
          .toArray();

        res.json({
          totalClubsJoined,
          totalEventsRegistered,
          upcomingEvents,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });
    // by newest
    //     app.get("/featured-clubs", async (req, res) => {
    //   const result = await db
    //     .collection("clubs")
    //     .find({ status: "approved" })
    //     .sort({ created_at: -1 })
    //     .limit(6)
    //     .toArray();

    //   res.send(result);
    // });
    // by most people
    app.get("/featured-clubs-newest", async (req, res) => {
      const result = await membershipCollection
        .aggregate([
          { $match: { status: "joined" } },
          {
            $group: {
              _id: "$clubId",
              totalMembers: { $sum: 1 },
            },
          },
          {
            $lookup: {
              from: "clubs",
              let: { clubId: "$_id" },
              pipeline: [
                {
                  $match: {
                    $expr: { $eq: ["$_id", { $toObjectId: "$$clubId" }] },
                  },
                },
              ],
              as: "club",
            },
          },
          { $unwind: "$club" },
          { $sort: { totalMembers: -1 } },
          { $limit: 6 },
          {
            $project: {
              _id: 0,
              clubId: "$club._id",
              clubName: "$club.clubName",
              category: "$club.category",
              coverImage: "$club.coverImage",
              totalMembers: 1,
            },
          },
        ])
        .toArray();

      res.send(result);
    });
    // get wishlist for members
    app.get("/my-wishlist", verifyJWT, async (req, res) => {
      const email = req.tokenEmail;
      const query = { userEmail: email };
      const result = await wishlistCollection.find(query).toArray();
      res.send(result);
    });
    app.post("/my-wishlist", verifyJWT, async (req, res) => {
      try {
        const wishlist = req.body;

        const result = await wishlistCollection.insertOne(wishlist);

        if (result.insertedId) {
          res.status(201).send({
            success: true,
            message: "Added to wishlist successfully",
            insertedId: result.insertedId,
          });
        } else {
          res.status(400).send({
            success: false,
            message: "Failed to add to wishlist",
          });
        }
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Server error while adding to wishlist",
        });
      }
    });
    // delete from wishlist
    app.delete("/my-wishlist", verifyJWT, async (req, res) => {
      const { userEmail, clubId } = req.body;
      const result = await wishlistCollection.deleteOne({ userEmail, clubId });
      if (result.deletedCount > 0) {
        res.send({ success: true });
      } else {
        res.status(404).send({ success: false, message: "Not found" });
      }
    });

    // ===== NOTIFICATION ENDPOINTS =====

    // Get notifications for a user
    app.get("/notifications/:email", verifyJWT, async (req, res) => {
      try {
        const userEmail = req.params.email;
        const notifications = await notificationCollection
          .find({ userId: userEmail })
          .sort({ createdAt: -1 })
          .limit(20)
          .toArray();

        res.send(notifications);
      } catch (error) {
        console.error("Error fetching notifications:", error);
        res.status(500).send({ message: "Failed to fetch notifications" });
      }
    });

    // Mark notification as read
    app.patch("/notifications/:id/read", verifyJWT, async (req, res) => {
      try {
        const notificationId = req.params.id;
        const result = await notificationCollection.updateOne(
          { _id: new ObjectId(notificationId) },
          { $set: { isRead: true, readAt: new Date() } }
        );

        res.send(result);
      } catch (error) {
        console.error("Error marking notification as read:", error);
        res.status(500).send({ message: "Failed to update notification" });
      }
    });

    // Mark all notifications as read for a user
    app.patch("/notifications/:email/read-all", verifyJWT, async (req, res) => {
      try {
        const userEmail = req.params.email;
        const result = await notificationCollection.updateMany(
          { userId: userEmail, isRead: false },
          { $set: { isRead: true, readAt: new Date() } }
        );

        res.send(result);
      } catch (error) {
        console.error("Error marking all notifications as read:", error);
        res.status(500).send({ message: "Failed to update notifications" });
      }
    });

    // Get unread notification count
    app.get(
      "/notifications/:email/unread-count",
      verifyJWT,
      async (req, res) => {
        try {
          const userEmail = req.params.email;
          const count = await notificationCollection.countDocuments({
            userId: userEmail,
            isRead: false,
          });

          res.send({ count });
        } catch (error) {
          console.error("Error getting unread count:", error);
          res.status(500).send({ message: "Failed to get unread count" });
        }
      }
    );
  } catch (error) {
    console.error("Database connection error:", error);
  }
}

// ===== CONTACT FORM ENDPOINT =====

run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello from Server..");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
