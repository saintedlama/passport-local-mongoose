import { router } from "./routes.js";
import passport from "passport";
import passportLocalMongoose from "../dist/index.js";
import { UserSchema, UserModel } from "./users.js";
import express from "express";
import session from "express-session";
import mongoose from 'mongoose';

mongoose.connect('mongodb://127.0.0.1:27017/passport-local-mongoose-example').then(() => console.log('Connected to MongoDB'));

const app = express();
app.use(express.json());

app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true },
  }),
);

UserSchema.plugin(passportLocalMongoose.default);
app.use(passport.initialize());
app.use(passport.session());
passport.use(UserModel.createStrategy());
passport.serializeUser(UserModel.serializeUser());
passport.deserializeUser(UserModel.deserializeUser());

app.use(router);

app.listen(3000, (err) => {
  if (err) {
    console.log("Error during startup", err);
    process.exit(1);
  }

  console.log("Server started on http://localhost:3000");
});
