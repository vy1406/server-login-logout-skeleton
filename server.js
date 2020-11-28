if (process.env.NODE_ENV !== 'production') {
	require('dotenv').config();
}

const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');

const initializePassport = require('./passport-config');
initializePassport(
	passport,
	email => users.find(user => user.email === email),
	id => users.find(user => user.id === id)
);
const users = []; // instead of db

app.set('view-engine', 'ejs'); // EJS
// telling our server we will be able to access inside our req inside post methods
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
	session({
		secret: process.env.SESSION_SECRET,
		resave: false, // should we resave our session variable if nothing has changed
		saveUninitialized: false // do you wanna save an empty value in a session if there is no value
	})
);
app.use(passport.initialize());
app.use(passport.session());

// form is using only form-post method.
// look at the index html
// and here. delete, app.delete
app.use(methodOverride('_method'));

// ---------------------
// middleware to check if user cannot visit pages when he is NOT logged in
// ---------------------
function checkNotAuthenticated(req, res, next) {
	if (req.isAuthenticated()) {
		return res.redirect('/');
	}
	next();
}

// ---------------------
// middleware to check if user cannot visit pages when he IS logged in
// ---------------------
function checkAuthenticated(req, res, next) {
	if (req.isAuthenticated()) {
		return next();
	}
	res.redirect('/login');
}
app.get('/', checkAuthenticated, (req, res) => {
	res.render('index.ejs', { name: req.user.name }); // EJS
});

app.get('/users', checkAuthenticated, (req, res) => {
	console.log(users);
	res.end();
});

app.get('/login', checkNotAuthenticated, (req, res) => {
	res.render('login.ejs'); // EJS
});

app.delete('/logout', (req, res) => {
	req.logOut();
	res.redirect('/login');
});

app.post(
	'/login',
	checkNotAuthenticated,
	passport.authenticate('local', {
		successRedirect: '/',
		failureRedirect: '/login',
		failureFlash: true
	})
);

app.get('/register', (req, res) => {
	res.render('register.ejs');
});

app.post('/register', checkNotAuthenticated, async (req, res) => {
	try {
		const hashedPassword = await bcrypt.hash(req.body.password, 10);
		users.push({
			id: Date.now().toString(),
			name: req.body.name,
			email: req.body.email,
			password: hashedPassword
		});

		res.redirect('/login');
	} catch (error) {
		res.redirect('/register');
	}
	console.log(users);
});

const port = process.env.PORT || 3000;

app.listen(port, () => console.log('App listening on port ' + port));
