const express = require('express');
const router = express.Router();

const validateToken = require("../auth-middleware").validateToken;
const User = require("./users.controllers")

router
    .route("/User/register")
    .post(User.createAccount) //Creating an Account

router
    .route("/auth/google")
    .get(User.googleAuth); // log in Using Google OAuth

router
    .route("/User/login")
    .post(User.login); //Log in

router
    .route("/User/recover")
    .post(User.recoverPassword); // Getting Token to recover password

router
    .route("/User/reset/:token")
    .post(User.resetPassword) //User Reset Password
router
    .route("/admin/User")
    .get(validateToken,User.findAll)// Getting User Info by Admin

router
    .route("/admin/update/User/id/:id")
    .get(validateToken,User.findByID)// list a User by ID
    .patch(validateToken, User.AdminUpdate) //Update a User by id
    .put(validateToken,User.AdminUpdate)   //Update a User by id
router
    .route("/admin/delete/User/id/:id")
    .delete(validateToken, User.AdminDelete); // Delete by id Delete

    
router
    .route("/admin/update/User/email/:email")
    .get(validateToken,User.findByEmail)// Finding a User by email
    .patch(validateToken, User.AdminUpdatebyemail)
    .put(validateToken, User.AdminUpdatebyemail)
   

router
    .route("/User/id/:id")
    .get(validateToken,User.findByID)// list a User by ID
    .patch(validateToken, User.Update) //Update a User by id
    .put(validateToken,User.Update)   //Update a User by id
    .delete(validateToken, User.delete); // Delete by id Delete

router
    .route("/User/email/:email")
    .get(validateToken,User.findByEmail)// list a User by email
    .patch(validateToken, User.Updatebyemail)
    .put(validateToken, User.Updatebyemail);



module.exports = router;