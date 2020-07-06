require("dotenv").config();
const User = require("./users.model");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const sgMail = require('@sendgrid/mail');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

//Creating a user
exports.createAccount = async (req,res,next)=>{
    try {
        let user = await User.findOne({email:req.body.email, isActive:true});
        if(user){
            res.status.json({
                success:false,
                message:"user is already Registered."
            })

        }
        else{
            const salt = await bcrypt.genSalt(12);
            hash = await bcrypt.hashSync(req.body.password, salt);
            const userDATA = {
				 
				 fname:req.body.fname,
				 lname:req.body.lname,
				 phone:req.body.phone,
				 email: req.body.email,
                 password:hash
            }
            const token = crypto.randomBytes(20).toString('hex');
            
            user = new User(userDATA);
            user.resetPasswordToken = token;
            user.resetPasswordExpires = Date.now() + 60000 * 20; //20 mins
            await user.save();
            
            return res.status(200).json({
              success:true,
              message: `Registration Successfull 
                     with email ` + user.email + '.'}); };


            

        
    }catch(error) {
		console.log(error);
		return res.status(500).json({
			
			
			success: false,
			error: error || 'An error occurred',
		});
	}
}

//user Login
exports.login = async (req, res) => {
	try {
		const loginData = req.body;

		//find an existing user
		const user = await User.findOne({
			email: req.body.email,
			isActive:true,
		});
		if (!user)
			return res.json({
				success: false,
				message: 'user not Found or Inactive',
			});

		bcrypt
			.compare(loginData.password, user.password)
			.then((result) => {
				if (result == false) {
					throw new Error('Email or Password Incorrect');
				}
				// Create a token
				const payload = {
					userID: user._id,
					userEmail: user.email,
					isUser: true,
				};
				const options = {
					expiresIn: process.env.JWT_EXPIRES_IN,
					issuer: process.env.JWT_ISSUER,
					subject: process.env.JWT_SUBJECT,
					audience: process.env.JWT_AUDIENCE,
				};

				const secret = process.env.JWT_SECRET;
				const token = jwt.sign(payload, secret, options);

				return res.status(200).json({
					success: true,
					message: 'Login Successful',
					user: {
                        id: user._id,
                        name:user.name,
						email: user.email,
			    		token: token,
					},
				});
			})
			.catch((err) => {
				return res.json({
					success: false,
					message: 'Email or Password Incorrect',
					error: err,
				});
			});
	} catch (error) {
		return res.json({
			success: false,
			error: error || 'An error occurred',
		});
	}
};

//Revover Password
exports.recoverPassword = async (req, res) => {
	try {
		// Check if Account exists with the Email
		let user = await User.findOne({ email: req.body.email});
		if (!user)
			return res.status(400).json({
				success: false,
				message: 'user Does not Exist',
			});

		//generate token to be sent to user's email
		let token = crypto.randomBytes(20).toString('hex');

		// override the cleartext password with the hashed one
		user.resetPasswordToken = token;
		user.resetPasswordExpires = Date.now() + 60000 * 20; //20 mins
		await user.save();

				 // send email
				 let link = " "  + "/resetPassword/" + user.resetPasswordToken;
				 const mailOptions = {
					 to: user.email,
					 from: "school@ideypay.com",
					 subject: "Password change request",
					 text:`Hi ${user.email} \n 
					 Please click on the following link  ${link} to reset your password. \n\n 
					 If you did not request this, please ignore this email and your password will remain unchanged.\n`,
					 };
                        
					
                              sgMail.send(mailOptions, (error, result) => {
                                if (error){
									console.log(error)	
								}  return res.status(500).json({message: error.message});
										
          
                                res.status(200).json({message: 'A reset link has been sent to ' + user.email + '.'}); });
        
  
	} catch (error) {
		return res.status(500).json({
			success: false,
			error: error || 'An error occurred',
		});
	}
};

//Reset Password 
exports.resetPassword = async (req, res) => {
	try {
		const user = await User.findOne({
			resetPasswordToken: req.params.token,
			resetPasswordExpires: {
				$gt: Date.now(),
			},
		});

		// user.password = await bcrypt.hash(req.body.password, 10);
		user.password = req.body.password;
		user.resetPasswordToken = undefined;
		user.resetPasswordExpires = undefined;
		await user.save();
		return res.status(200).json({
			success: true,
			message: 'Password reset successful',
		});
	} catch (error) {
		return res.status(500).json({
			success: false,
			error: error || 'An error occurred',
		});
	}
};

// Admin to Retrieve and return all users from the database.
exports.findAll = (req, res) => {
	try {
		const payload = req.decoded;
		if (payload && payload.isAdmin) {
			User.find({ isSuperAdmin: false })
				.then((users) => {
					return res.status(200).send({
						success: true,
						users,
					});
				})
				.catch((err) => {
					return res.status(500).send({
						message:
							err.message || 'Some error occurred while retrieving all users.',
					});
				});
		} else {
			return res.status(401).json({
				success: false,
				message: 'Authentication Error | Unauthorised',
			});
		}
	} catch (error) {
		return res.status(500).json({
			success: false,
			error: error || 'An error occurred',
		});
	}
};

//Admin Finding a single user by user Email 
exports.findByEmail = (req, res) => {
	try {
        const payload = req.decoded;
        if (payload && payload.isAdmin) {
		User.findOne({ email: req.params.email })
			.select('-password')
			.then((user) => {
				if (!user) {
					return res.status(404).send({
						success: false,
						message: 'user not found',
					});
				}
				res.status(200).send({
					success: true,
					user,
				});
			})
			.catch((err) => {
				return res.status(500).send({
					message: err || 'Error retrieving user with email: ' + req.params.email,
				});
            });
        }
	} catch (error) {
		return res.status(500).json({
			success: false,
			error: error || 'An error occurred',
		});
	}
};

//Admin Finding a single user by user id
exports.findByID = (req, res) => {
	try {
        const payload = req.decoded;
        if (payload && payload.isAdmin) {
		User.findOne({ _id: req.params.id })
			.select('-password')
			.then((user) => {
				if (!user) {
					return res.status(404).send({
						success: false,
						message: 'user not found',
					});
				}
				res.status(200).send({
					success: true,
					user,
				});
			})
			.catch((err) => {
				return res.status(500).send({
					message: 'Error retrieving user with email: ' + req.params.email,
				});
			}); }
	} catch (error) {
		return res.status(500).json({
			success: false,
			error: error || 'An error occurred',
		});
	}
};

//Admin Update a user identified by the userId in the request
exports.AdminUpdate = async (req, res) => {
	try {
		const payload = req.decoded;

		if (payload) {
			const user = await User.findById(payload.adminID);

			if (!user) {
				return res.status(404).json({
					success: false,
					message: 'user does not exists',
				});
			}

			let body = req.body;
			body.password = user.password;

			user.updateOne({ _id: user._id }, body, { new: true })
				.then((user) => {
					return res.status(200).json({
                        success: true,
                        user,
						message: 'user Details successfully updated',
					});
				})
				.catch((err) => {
					return res.status(500).json({
						success: false,
						message: 'An error occurred when updating user',
						error: err || 'An error occurred when updating user',
					});
				});
		} else {
			return res.status(401).json({
				success: false,
				message: 'Authentication Error | Unauthorised',
			});
		}
	} catch (error) {
		return res.status(500).json({
			success: false,
			error: error || 'An error occurred',
		});
	}
};

//Admin Updating user identified by the user email in the request
exports.AdminUpdatebyemail = async (req, res) => {
	try {
		const payload = req.decoded;

		if (payload) {
			const user = await User.findById(payload.adminEmail);

			if (!user) {
				return res.status(404).json({
					success: false,
					message: 'user does not exists',
				});
			}

			let body = req.body;
			body.password = user.password;

			User.updateOne({ email: user.email }, body, { new: true })
				.then((user) => {
					return res.status(200).json({
						success: true,
						message: 'user Details successfully updated',
					});
				})
				.catch((err) => {
					return res.status(500).json({
						success: false,
						message: 'An error occurred when updating user',
						error: err || 'An error occurred when updating user',
					});
				});
		} else {
			return res.status(401).json({
				success: false,
				message: 'Authentication Error | Unauthorised',
			});
		}
	} catch (error) {
		return res.status(500).json({
			success: false,
			error: error || 'An error occurred',
		});
	}
};

// Updating a user identified by the userId in the request
exports.Update = async (req, res) => {
	try {
		const payload = req.decoded;

		if (payload) {
			const user = await User.findById(payload.userID);

			if (!user) {
				return res.status(404).json({
					success: false,
					message: 'user does not exists',
				});
			}

			let body = req.body;
			body.password = user.password;

			User.updateOne({ _id: user._id }, body, { new: true })
				.then((user) => {
					return res.status(200).json({
						success: true,
						message: 'user Details successfully updated',
					});
				})
				.catch((err) => {
					return res.status(500).json({
						success: false,
						message: 'An error occurred when updating user',
						error: err || 'An error occurred when updating user',
					});
				});
		} else {
			return res.status(401).json({
				success: false,
				message: 'Authentication Error | Unauthorised',
			});
		}
	} catch (error) {
		return res.status(500).json({
			success: false,
			error: error || 'An error occurred',
		});
	}
};

//Update a user identified by the user email in the request
exports.Updatebyemail = async (req, res) => {
	try {
		const payload = req.decoded;

		if (payload) {
			const user = await User.findById(payload.userEmail);

			if (!user) {
				return res.status(404).json({
					success: false,
					message: 'user does not exists',
				});
			}

			let body = req.body;
			body.password = user.password;

			User.updateOne({ email: user.email }, body, { new: true })
				.then((user) => {
					return res.status(200).json({
						success: true,
						message: 'user Details successfully updated',
					});
				})
				.catch((err) => {
					return res.status(500).json({
						success: false,
						message: 'An error occurred when updating user',
						error: err || 'An error occurred when updating user',
					});
				});
		} else {
			return res.status(401).json({
				success: false,
				message: 'Authentication Error | Unauthorised',
			});
		}
	} catch (error) {
		return res.status(500).json({
			success: false,
			error: error || 'An error occurred',
		});
	}
};

// Admin Deleting a users Account By ID
exports.AdminDelete = async (req, res) => {
	try {
        const payload = req.decoded;
        if (payload && payload.isAdmin) {
		const user = await User.findOne({
			_id: req.params.id,
			isActive: true,
		}).select('-password');
		if (!user) {
			return res.status(404).json({
				success: false,
				message: 'user does not exists',
			});
		}

		User.findOneAndUpdate(
			{ _id: user._id },
			{
				isActive: false,
			},
			{ new: true }
		)
			.then((result) => {
				return res.status(200).json({
					success: true,
					message: 'user Deleted Successfully',
				});
			})
			.catch((err) => {
				return res.status(500).send({
					message: '`Error updating user',
					error: err,
				});
			}); }
	} catch (error) {
		return res.status(500).json({
			success: false,
			error: error || 'An error occurred',
		});
	}
};

// user Deleting their Account 
exports.delete = async (req, res) => {
	try {
        const payload = req.decoded;
        if (payload && payload.isUser) {
		const user = await User.findOne({
			_id: req.params.id,
			isActive: true,
		}).select('-password');
		if (!user) {
			return res.status(404).json({
				success: false,
				message: 'user does not exists',
			});
		}

		User.findOneAndUpdate(
			{ _id: user._id },
			{
				isActive: true,
			},
			{ new: true }
		)
			.then((result) => {
				return res.status(200).json({
					success: true,
					message: 'user Deleted Successfully',
				});
			})
			.catch((err) => {
				return res.status(500).send({
					message: '`Error updating user',
					error: err,
				});
			}); }
	} catch (error) {
		return res.status(500).json({
			success: false,
			error: error || 'An error occurred',
		});
	}
};


