require('./utils.js');

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();

const port = process.env.PORT || 3020;

const Joi = require('joi');

const expireTime = 60 * 60 * 1000 //1 hour (minutes * seconds * milliseconds)

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}))

app.use(express.static(__dirname + "/public"));

app.get('/', (req, res) => {
    var html = '';

    if (!req.session.authenticated) {
        // res.redirect('/login');
        html += `
            <button onclick="window.location.href = '/signup'">Sign up</button><br>
            <button onclick="window.location.href = '/login'">Log in</button>`;
    } else {
        html += `
            Hello, ${req.session.name}!<br>
            <button onclick="window.location.href = '/members'">Go to members area</button><br>
            <button onclick="window.location.href = '/logout'">Logout</button>`;
    }

    res.send(html);

    // if (req.session.numPageHits == null) {
    //     req.session.numPageHits = 0;
    // } else {
    //     req.session.numPageHits++;
    // }
    // // numPageHits++;
    // res.send('You have visited ' + req.session.numPageHits + ' times');
})

app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req, res) => {
    var color = req.query.color;
    res.send("<h1 style='color: " + color + ";'>Mike</h1>");
})

app.get('/pics/:id', (req, res) => {
    var pic = req.params.id;

    if (pic == 1) {
        res.send("Broccoli: <img src='/broccoli.jpg' style='width: 250px;'>");
    } else if (pic == 2) {
        res.send("Carrot: <img src='/carrot.jpg' style='width: 250px;'>");
    } else {
        res.send("Invalid id: " + pic);
    }
})

app.get('/contact', (req, res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' placeholder='email'>
            <button>Submit</button>
        </form>`;

    if (missingEmail) {
        html += "<br> email is required";
    }

    res.send(html);
    // res.send("Email: <input></input></br><input type='submit'></input>");
})

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;

    if (!email) {
        res.redirect('/contact?missing=1');
    } else {
        res.send("Thank you fo subscribing with your email: " + email);
    }
})

app.get('/signup', (req, res) => {
    var html = `
        Create user:
        <form action='/signupSubmit' method='post'>
            name:
            <input name='name' placeholder='name'></br>
            email:
            <input type='email' name='email' placeholder='email'></br>
            password:
            <input type='password' name='password' placeholder='password'></br>
            <button>Submit</button>
        </form>`;

    res.send(html);
})

app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().max(20).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        var html = '';

        console.log(validationResult.error);
        if (validationResult.error.details[0].type == 'string.alphanum') {
            html += 'Fields must contain only alphanumeric characters.<br>';
        }
        if (validationResult.error.details[0].type == 'string.email') {
            html += 'Email invalid.<br>';
        }
        if (name == '') {
            html += 'Name is required.<br>';
        }
        if (email == '') {
            html += 'Email is required.<br>';
        }
        if (password == '') {
            html += 'Password is required.<br>';
        }

        html += "<br><a href='/signup'>Try again</a>"

        res.send(html);
    } else {
        var hashedPassword = await bcrypt.hash(password, saltRounds);

        await userCollection.insertOne({ name: name, email: email, password: hashedPassword });
        console.log("Inserted user");

        res.redirect('/members');
    }


})

app.get('/login', (req, res) => {
    var html = `
        Log in:
        <form action='/loginSubmit' method='post'>
            email:
            <input type='email' name='email' placeholder='email'></br>
            password:
            <input type='password' name='password' placeholder='password'></br>
            <button>Submit</button>
        </form>`;

    res.send(html);
})

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            email: Joi.string().email().max(20).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);

        var html = `
            Invalid characters in email or password.<br><br>
            <a href='/login'>Try again</a>`

        res.send(html);
        return;
    }

    const result = await userCollection.find({ email: email }).project({ name: 1, password: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");

        var html = `
            Invalid email/password combination.<br><br>
            <a href='/login'>Try again</a>`

        res.send(html);
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    } else {
        console.log("incorrect password");

        var html = `
            Invalid email/password combination.<br><br>
            <a href='/login'>Try again</a>`

        res.send(html);
        return;
    }
})

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }

    var html = `<h2>Hello, ${req.session.name}!</h2>How about a vegetable?<br>`;

    var pics = ['/broccoli.jpg', '/carrot.jpg', '/pepper.jpg'];

    html += `<img src='${pics[Math.floor(Math.random() * 3)]}' style='width: 250px;'>`;

    console.log(html);

    res.send(html);
})

app.get('/logout', (req, res) => {
    req.session.destroy();
    // var html = `
    // You are logged out.
    // `;
    // res.send(html);
    res.redirect('/');
});

app.get('*', (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})



app.listen(port, () => {
    console.log('Node application listening on port ' + port);
})