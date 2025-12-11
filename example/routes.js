import Router from "express";
import passport from "passport";

const router = Router();

router.post("/login", (req, res, next) => {
  console.log("Authenticating user...");

  passport.authenticate("local", (err, user) => {
    if (err) {
      console.log("Error during authentication", err);
      return next(err);
    }

    if (!user)
      return res
        .status(403)
        .json({ message: "Invalid credentials" });

    req.logIn(user, async (err) => {
      if (err) {
        console.log("Error during login", err);
        return next(err);
      }

      console.log("User authenticated and logged in successfully", user);
      return res.status(200).json({ message: "User authenticated and logged in successfully" });
    });
  })(req, res, next);
});

export { router };