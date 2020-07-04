const jwt = require('jsonwebtoken');
require('dotenv').config();

module.exports = {
	validateToken: (req, res, next) => {
		const authorizationHeader = req.headers.authorization;
		let result;

		if (authorizationHeader) {
			const token = req.headers.authorization.split(' ')[1]; // Bearer <token>
			const options = {
				expiresIn: process.env.JWT_EXPIRES_IN,
				issuer: process.env.JWT_ISSUER,
				subject: process.env.JWT_SUBJECT,
				audience: process.env.JWT_AUDIENCE,
			};
			try {
				// verify makes sure that the token hasn't expired and has been issued by us
				result = jwt.verify(token, process.env.JWT_SECRET, options);

				// Let's pass back the decoded token to the request object
				req.decoded = result;

				// We call next to pass execution to the subsequent middleware
				return next();
			} catch (err) {
				// Throw an error just in case anything goes wrong with verification
				return res.status(500).json(err);
			}
		}

		return res.status(401).json({
			success: false,
			errors: `Authentication error; Token required.`,
		});
	},
};
