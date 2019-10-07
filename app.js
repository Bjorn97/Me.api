const express = require("express");
const morgan = require('morgan');
const cors = require('cors');
const app = express();
const index = require('./routes/index');
const hello = require('./routes/hello');
const bodyParser = require("body-parser");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const saltRounds = 10;
app.use(bodyParser.json()); // for parsing application/json
app.use(bodyParser.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded
app.use('/', index);
app.use('/hello', hello);
const port = 1337;

// don't show the log when it is test
if (process.env.NODE_ENV !== 'test') {
    // use morgan to log at command line
    app.use(morgan('combined')); // 'combined' outputs the Apache style LOGs
}

// Add a route
app.get("/", (request, response) => {
    const data = {
        data: {
            msg: "Hello World"
        }
    };

    response.json(data);
});

app.get("/reports/week/1", (request, response) => {
    const data = {
        data: {
            msg: "Hello World"
        }
    };

    response.json(data);
});

app.get("/reports/week/2", (request, response) => {
    const data = {
        data: {
            msg: "Hello World"
        }
    };

    response.json(data);
});

app.post("/register", (request, response) => {
    const sqlite3 = require('sqlite3').verbose();
    const db = new sqlite3.Database('./db/texts.sqlite');
    const emailRe = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/;
    const passRe = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}/;
    const nameRe = /[^<>/]+/;
    const dateRe = /(?:19|20)\d\d/;

    if (!emailRe.test(request.body.email)) {
        return response.json({
            data: {
                msg: "500 server error",
                err: err
            }
        });
    }
    if (!passRe.test(request.body.password)) {
        return response.json({
            data: {
                msg: "500 server error",
                err: err
            }
        });
    }
    if (!nameRe.test(request.body.name)) {
        return response.json({
            data: {
                msg: "500 server error",
                err: err
            }
        });
    }
    if (!dateRe.test(request.body.date)) {
        return response.json({
            data: {
                msg: "500 server error",
                err: err
            }
        });
    }
    bcrypt.hash(request.body.password, saltRounds, function(err, hash) {
        db.run(
            "INSERT INTO users (email,password,name,date) VALUES (?, ?, ?, DATE(?))",
            request.body.email,
            hash,
            request.body.name,
            request.body.date,
            (err) => {
                if (err) {
                    // returnera error
                    return response.json({
                        data: {
                            msg: "500 server error",
                            err: err
                        }
                    });
                }
                // returnera korrekt svar
                return response.json({
                    data: {
                        msg: "200 okay",
                    }
                });
            }
        );
    });
});

app.post("/login", (request, response) => {
    bcrypt.compare(request.body.password, hash, function(err, res) {
    // res innehåller nu true eller false beroende på om det är rätt lösenord.
    const payload = { email: "user@example.com" };
    const secret = process.env.JWT_SECRET;

    const token = jwt.sign(payload, secret, { expiresIn: '1h'});
    });
    response.status(201).json({
        data: {
            msg: "Got a POST requestuest, sending back 201 Created",
            token: token
        }
    });
});


app.get("/hello/:msg", (request, response) => {
    const data = {
        data: {
            msg: request.params.msg
        }
    };

    response.json(data);
});

// Testing routes with method
app.get("/hello/Jag%20kan%20svenska%20%C3%85%C3%84%C3%96", (request, response) => {
    response.json({
        data: {
            msg: "Got a GET requestuest"
        }
    });
});

app.post("/user", (request, response) => {
    const sqlite3 = require('sqlite3').verbose();
    const db = new sqlite3.Database('./db/texts.sqlite');

    db.run(
        "INSERT INTO users (email, password, name, date) VALUES (?, ?, ?, DATE(?))",
        (err) => {
            if (err) {
                // returnera error
                return response.json({
                    data: {
                        msg: "500 server error",
                        err: err
                    }
                });
            }

            // returnera korrekt svar
            return response.json({
                data: {
                    msg: "200 okay",
                }
            });
        }
    );
});

app.put("/user", (request, response) => {
    response.json({
        data: {
            msg: "Got a PUT requestuest"
        }
    });
});

app.delete("/user", (request, response) => {
    response.json({
        data: {
            msg: "Got a DELETE requestuest"
        }
    });
});

app.get("/user", (request, response) => {
    response.json({
        data: {
            msg: "Got a GET requestuest, sending back default 200"
        }
    });
});

app.post("/user", (request, response) => {
    response.status(201).json({
        data: {
            msg: "Got a POST requestuest, sending back 201 Created"
        }
    });
});

app.put("/user", (request, response) => {
    // PUT requestuests should return 204 No Content
    response.status(204).send();
});

app.delete("/user", (request, response) => {
    // DELETE requestuests should return 204 No Content
    response.status(204).send();
});

app.use((request, response, next) => {
    var err = new Error("Not Found");
    err.status = 404;
    next(err);
});

app.use((err, request, response, next) => {
    if (response.headersSent) {
        return next(err);
    }

    response.status(err.status || 500).json({
        "errors": [
            {
                "status": err.status,
                "title":  err.message,
                "detail": err.message
            }
        ]
    });
});

app.post("/reports", checkToken, (request, response) => {
    response.status(201).json({
        data: {
            msg: "Got a POST requestuest, sending back 201 Created"
        }
    });
});

// Start up server
app.listen(port, () => console.log(`Example API listening on port ${port}!`));

function checkToken(request, result, next) {
    const token = req.headers['x-access-token'];

    jwt.verify(token, process.env.JWT_SECRET, function(err, decoded) {
        if (err) {
            // send error response
        }

        // Valid token send on the request
        next();
    });
}
