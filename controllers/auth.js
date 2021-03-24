const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { promisify } = require("util");


const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
});


exports.register = (req, res) => {
    console.log(req.body);

    //const name = req.body.name
    const { name, email, password, passwordConfirm } = req.body;

    db.query('SELECT email FROM users WHERE email = ?', [email], async(error, results) => {
        if(error){
            console.log(error);
        }

        // The email is already in the database
        if(results.length > 0){
            return res.render('register',{
                message: 'That email is already in use'
            });
        }
        else if( password !== passwordConfirm){
            return res.render('register',{
                message: 'The password do not match'
            });
        }

        let hashedPassword = await bcrypt.hash(password, 8);
        console.log(hashedPassword);

        db.query('INSERT INTO users SET ?', {name: name, email: email, password:hashedPassword}, (error, results) => {
            if(error){
                console.log(error);
            }
            else{
                return res.render('register',{
                    message: 'User registered'
                })
            }
        })
    });

}

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // There is no email or password
        if( !email || !password){
            return res.status(400).render('login',{
                message: 'Email and Password cannot be empty'
            })
        }

        db.query('SELECT * FROM users WHERE email = ?', [email], async(error, results) => {
            console.log(results);
            if ( !results || !(await bcrypt.compare(password, results[0].password) )){
                res.status(401).render('login', {
                    message: 'Email or Password is incorrect'
                })
            }
            else{
                const id = results[0].id;

                const token = jwt.sign({ id }, process.env.JWT_SECRET, {
                    expiresIn: process.env.JWT_EXPIRES_IN
                })

                console.log("The token is " + token);

                const cookieOptions = {
                    expires: new Date(
                        Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
                    ),
                    httpOnly: true
                }

                res.cookie('jwt', token, cookieOptions);
                res.status(200).redirect("/");
            }
        })

    } catch (error) {
        console.log(error);
    }
}

exports.isLoggedIn = async (req, res, next) => {
    if(req.cookies.jwt) {
        try {
            //(1) verify the token
            const decoded = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRET);
            console.log(decoded);

            //(2) check if the user still exists
            db.query('SELECT * FROM users WHERE id = ?', [decoded.id], (error, result) => {
                console.log(result);

                if(!result){
                    return next();
                }

                req.user = result[0];
                return next();

            })
        } catch (error) {
            console.log(error);
            return next();
        }
    }
    else{
        next();
    }
    
}

exports.logout = async(req, res) => {
    res.cookie('jwt', 'logout', {
        expires: new Date(Date.now() + 2*1000),
        httpOnly: true
    });

    res.status(200).redirect('/');
}