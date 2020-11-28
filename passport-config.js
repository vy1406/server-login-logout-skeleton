const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

function initialize(passport, getUserByEmail, getUserById) {
	const authenticateUser = async (email, password, doneCb) => {
		const user = getUserByEmail(email);
		if (user == null) {
			return doneCb(null, false, { msg: 'no user with that email' });
		}

		try {
			if (await bcrypt.compare(password, user.password)) {
				return doneCb(null, user);
			} else {
				return doneCb(null, false, { msg: 'password did not match' });
			}
		} catch (e) {
			return doneCb(e);
		}
	};
	// 'email' is from the client's form, no need to pass password,
	// because our client password is the same field name as localStrategy password
	passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser));
	passport.serializeUser((user, doneCb) => doneCb(null, user.id));
	passport.deserializeUser((id, doneCb) => {
		return doneCb(null, getUserById(id));
	});
}

module.exports = initialize;
