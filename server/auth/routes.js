var router = require('express').Router();
var verifyUser = require('./auth').verifyUser;
var controller = require('./controller');
var User = require('../api/users/userModel');
var config = require('../config/config');
var jwt = require('jsonwebtoken');

exports.router = function (passport) {
    router.get('/', function(req, res) {
		res.status(200).send('Index page');
	});

	// PROFILE SECTION =========================
	router.get('/profile', passport.authenticate('jwt', {session: false}), function(req, res) {		
        res.send(req.user);       
	});

	// LOGOUT ==============================
	router.get('/logout', function(req, res) {
		req.logout();
		res.redirect('/login');
	});

    router.get('/login', function(req, res) {
        res.status(200).send('Login page');
    });

    router.post('/signup', passport.authenticate('local-signup', {
        successRedirect: '/users', // redirect to the secure profile section
        failureRedirect: '/signup', // redirect back to the signup page if there is an error
        failureFlash: true // allow flash messages
    }));

    router.post('/login', function (req, res, next) {
        passport.authenticate('local-login', {session:false}, (err, user, info) => {
        if (err || !user) {
            return res.status(400).json({
                message: 'Something is not right',
                user   : user
            });
        }
        req.login(user, {session: false}, (err) => {
           if (err) {
               res.send(err);
           }
           // generate a signed json web token with the contents of user object and return it in the response
           const token = jwt.sign(user.toJSON(), config.secrets.jwt, {expiresIn: 604800 });
           return res.json({user, token});
        });
    })(req, res);
    });

    router.get('/auth/facebook', passport.authenticate('facebook', { scope: 'email', session:'false' }));

    router.get('/auth/facebook/callback',
        passport.authenticate('facebook', {
            successRedirect: '/profile',
            failureRedirect: '/'
    }));

    router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] , session:'false' }));

    // the callback after google has authenticated the user
    router.get('/auth/google/callback',
        passport.authenticate('google', {
            successRedirect: '/profile',
            failureRedirect: '/'
        }));


    router.get('/connect/facebook', passport.authorize('facebook', { scope: 'email' , session:'false' }));

    // handle the callback after facebook has authorized the user
    router.get('/connect/facebook/callback',
        passport.authorize('facebook', {
            successRedirect: '/profile',
            failureRedirect: '/'
        }));

    router.get('/connect/google', passport.authorize('google', { scope: ['profile', 'email'], session:'false'  }));

    // the callback after google has authorized the user
    router.get('/connect/google/callback',
        passport.authorize('google', {
            successRedirect: '/profile',
            failureRedirect: '/'
        // }),function(req, res) {
        //     const token = jwt.sign(user, config.secrets.jwt);
        //     return res.json({user, token});
        // });
    }));


    router.get('/unlink/facebook', function (req, res) {
        var user = req.user;
        user.facebook.token = undefined;
        user.save(function (err) {
            res.redirect('/profile');
        });
    });

    router.get('/unlink/google', function (req, res) {
        var user = req.user;
        user.google.token = undefined;
        user.save(function (err) {
            res.redirect('/profile');
        });
    });

    return router;
};

exports.isLoggedIn = function isLoggedIn(req, res, next) {
    if (req.isAuthenticated())
        return next();

    res.status(401).send('Unauthorized Access requested.');
}