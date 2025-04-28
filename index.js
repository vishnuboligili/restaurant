import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";

import rateLimit from "express-rate-limit";
import { Strategy } from "passport-local";
import session from "express-session";
import flash from "express-flash";
import nodemailer from "nodemailer";
import crypto from "crypto";
import multer from "multer";
import { fileURLToPath } from "url";
import path, { dirname } from "path";
import { name } from "ejs";

// Fix __dirname for ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const rounds = 12;
const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use("/uploads", express.static("public/uploads"));
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));

const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "project",
    password: "password",
    port: 5432,
});

db.connect()
    .then(() => console.log("✅ Connected to PostgreSQL"))
    .catch((err) => console.error("❌ Database connection error:", err));


const storage = multer.diskStorage({
    destination: path.resolve(__dirname, "public", "uploads"), // Corrected path
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage });
    
app.use(session({
    secret: "TOPSECRET",
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 3600000, // 1 hour (in milliseconds)
        httpOnly: true, // Prevent client-side JavaScript from accessing the cookie
        secure: false,  // Set to `true` if using HTTPS
    }
}));

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465, // Use 465 for `secure: true`, or 587 for `secure: false`
    secure: true, // `true` for 465, `false` for 587
    auth: {
        user: "boligilivishnuvardhan@gmail.com",
        pass: "llts jfzt vldz exrl",
    },
});

transporter.verify((error, success) => {
    if (error) {
        console.error("❌ Nodemailer Error:", error);
    } else {
        
        console.log("✅ Nodemailer is ready to send emails!");
    }
});
app.get("/",(req,res)=>{
    if(!req.user){
        return res.render("home.ejs",{
            use:null,
        });
    }
    else{
        console.log(req.user);
        return res.render("home.ejs",{
            use:req.user.username,
        });
    }
});
app.get("/login", checkAuthenticated, (req, res) => {
    const errorMessages = req.flash("error");
    const successMessages = req.flash("success-message");

    res.render("login.ejs", { 
        errors: errorMessages, 
        success: successMessages.length > 0 ? successMessages[0] : null 
    });
});


const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login attempts per window
    message: "Too many login attempts, please try again later."
});

app.post("/login", loginLimiter, passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
}));

app.get("/register",checkAuthenticated,(req,res)=>{
    res.render("register.ejs",{
        em:null,
        user:null
    });
});
app.post("/register", async (req, res) => {
    const { email, password, username } = req.body;
    console.log(email, password, username);

    const verification_code = Math.floor(100000 + Math.random() * 900000);
    console.log(verification_code);

    try {
        const resultUserName = await db.query("SELECT * FROM users WHERE username=$1;", [username]);
        if (resultUserName.rows.length > 0 && resultUserName.rows[0].is_verified) {
            console.log("Username already verified");
            return res.render("register.ejs", { user: true, em: null });
        }

        const resultEmail = await db.query("SELECT * FROM users WHERE email=$1;", [email]);
        if (resultEmail.rows.length > 0 && resultEmail.rows[0].is_verified) {
            console.log("Email already verified");
            return res.render("register.ejs", { em: true, user: null });
        }

        

        // Delete unverified users before inserting a new one
        if (resultEmail.rows.length > 0 && !resultEmail.rows[0].is_verified) {
            await db.query("DELETE FROM users WHERE email=$1;", [email]);
        }
        if (resultUserName.rows.length > 0 && !resultUserName.rows[0].is_verified) {
            await db.query("DELETE FROM users WHERE username=$1;", [username]);
        }

        // Hash password and insert new user
        const hash = await bcrypt.hash(password, rounds);
        await db.query(
            "INSERT INTO users (email, username, password, is_verified, forgot, verification_token, mobile) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            [email, username, hash, false, true, verification_code, null] // ✅ Added 'null' for mobile
        );
        

        // Send verification email
        await transporter.sendMail({
            from: "boligilivishnuvardhan@gmail.com",
            to: email,
            subject: "Email Verification",
            text: `Email verification from VISHNU RESTAURANTS`,
            html: `<p>Verification Code: ${verification_code}</p>`,
        });

        req.flash("success-message", "Check your email to verify your account.");
        return res.render("otp.ejs", { em: email, error: null }); // ✅ Use return
    } catch (err) {
        console.error(err);
        if (!res.headersSent) {
            return res.status(500).send("Internal Server Error"); // ✅ Ensure error response is sent
        }
    }
});

app.get("/otp",(req,res)=>{
    res.render("otp.ejs",{
        em:"",
        error:null,
    })
});

app.post("/otp", async (req, res) => {
    const { email, n1, n2, n3, n4,n5,n6} = req.body;
    const enteredOTP = `${n1}${n2}${n3}${n4}${n5}${n6}`;
    console.log(enteredOTP)
    try {
        // Get stored OTP
        const result = await db.query("SELECT verification_token FROM users WHERE email=$1;", [email]);

        if (result.rows.length === 0) {
            req.flash("error", "Invalid email address.");
            return res.redirect("/register");
        }

        const storedOTP = result.rows[0].verification_token.toString();

        if (enteredOTP === storedOTP) {
            // Mark user as verified
            await db.query("UPDATE users SET is_verified=$1,forgot=$2 , verification_token=NULL WHERE email=$3;", [true,true, email]);
            req.flash("success", "Email verified! You can now log in.");
            res.redirect("/login");
        } else {
            req.flash("error", "Invalid OTP. Please try again.");
            res.render("otp.ejs", { em: email ,error:true});
        }
    } catch (err) {
        console.error(err);
        res.redirect("/register");
    }
});
app.get("/profile",(req,res)=>{
    console.log(req.user);
    if(req.user){
        res.render("profile.ejs",{
            user:req.user.username,
            email:req.user.email,
            mobile:req.user.mobile
        })
    }
    else{
        res.redirect("/");
    }
})

app.get("/edit",(req,res)=>{
    console.log(req.user);
    if(req.user){
        res.render("edit.ejs",{
            user:req.user.username,
            email:req.user.email,
            mobile:req.user.mobile
        })
    }
    else{
        res.redirect("/");
    }
})
app.post("/edit", async (req, res) => {
    const { user, email, mobile } = req.body;
    
    console.log("Received Data:", req.body); // Debugging

    let phone = mobile && mobile.trim() !== "" ? mobile.trim() : null;
    console.log(phone);
    try {
        const result = await db.query(
            "UPDATE users SET mobile=$1 WHERE email=$2 RETURNING *;",
            [phone, email]
        );

        if (result.rowCount === 0) {
            console.log("No user found with this email.");
            return res.status(400).send("User not found.");
        }

        return res.render("profile.ejs", {
            user: user,
            email: email,
            mobile: phone,
        });
    } catch (err) {
        console.error("Database error:", err);
        return res.status(500).send("Server error.");
    }
});
app.get("/forgot",(req,res)=>{
    res.render("forgot.ejs",{
        errors:null
    })
})
app.post("/forgot",async (req,res)=>{
    const email=req.body.email;
    try{
        const result = await db.query(
            "SELECT * FROM users WHERE email=$1;", [email]
        );
        if(result.rows.length==0||!(result.rows[0].is_verified)){
            return res.render("forgot.ejs",{
                errors:"1"
            })
        }
        const verification_code = Math.floor(100000 + Math.random() * 900000);
        console.log(verification_code);
        try{

            const change=await db.query(
                "UPDATE users SET verification_token=$1,forgot=$2 WHERE email=$3 RETURNING *;",
                [verification_code,false,email]
            );
            await transporter.sendMail({
                from: "boligilivishnuvardhan@gmail.com",
                to: email,
                subject: "Email Verification",
                text: `Email verification from VISHNU RESTAURANTS`,
                html: `<p>Verification Code: ${verification_code}</p>`,
            });

            return res.render("forgotcheck.ejs", { em: email, error: null });
        }
        catch(err){
            console.log(err);
        }

    }
    catch(err){
        console.log(err);
    }
})
app.get("/forgotcheck",(req,res)=>{
    res.render("forgotcheck.ejs",{
        em:"",
        error:null,
    })
})
app.post("/forgotcheck", async (req, res) => {
    const { email, n1, n2, n3, n4, n5, n6 } = req.body;
    const enteredOTP = `${n1}${n2}${n3}${n4}${n5}${n6}`;

    console.log("Entered OTP:", enteredOTP);

    try {
        // Get stored OTP from database
        const result = await db.query("SELECT verification_token FROM users WHERE email=$1;", [email]);

        if (result.rows.length === 0) {
            req.flash("error", "Invalid email address.");
            return res.redirect("/forgot");
        }

        const storedOTP = result.rows[0].verification_token?.toString();

        if (enteredOTP === storedOTP) {
            // Mark the user as eligible for password reset
            await db.query("UPDATE users SET forgot=$1, verification_token=NULL WHERE email=$2;", [true, email]);

            req.flash("success", "OTP verified! Set a new password.");
            return res.redirect(`/password?email=${encodeURIComponent(email)}`);
        } else {
            req.flash("error", "Invalid OTP. Please try again.");
            return res.render("forgotcheck.ejs", { em: email, error: true });
        }
    } catch (err) {
        console.error("Error verifying OTP:", err);
        return res.redirect("/forgot");
    }
});


app.get("/password", (req, res) => {
    const email = req.query.email; // Ensure email is passed as a query parameter
    if (!email) {
        req.flash("error", "Invalid access to password reset.");
        return res.redirect("/forgot");
    }
    res.render("password.ejs", { em: email, error: null });
});


app.post("/password", async (req, res) => {
    const { email, password} = req.body;
    try {
        const hash = await bcrypt.hash(password, rounds);

        // Update the password in the database
        const result = await db.query(
            "UPDATE users SET password=$1, forgot=$2 WHERE email=$3 RETURNING *;",
            [hash, true, email]
        );

        if (result.rowCount === 0) {
            req.flash("error", "No user found with this email.");
            return res.redirect("/forgot");
        }

        req.flash("success", "Password reset successfully! You can now log in.");
        return res.redirect("/login");
    } catch (err) {
        console.error("Error updating password:", err);
        return res.status(500).send("Server error.");
    }
});

app.get("/about",async(req,res)=>{
    
    try{
        const staff= await db.query("select * from staff order by id asc");
        if(req.user){
            return res.render("about.ejs",{
                use:req.user.username,
                staff:staff.rows,
            })
        }
        else{
            return res.render("about.ejs",{
                use:null,
                staff:staff,
            })
        }
    }catch(err){
        console.log(err);
        res.redirect("/");
    }
})

app.get("/menu", async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM products ORDER BY id ASC;");
        const dishes = result.rows;
        if(!req.user){
            return res.render("menu.ejs", { 
                dishes:dishes,
                user:null,
            });
        }
        else{
            return res.render("menu.ejs", { 
                dishes:dishes,
                user:req.user.username,
            });
            
        }
        
    } catch (err) {
        console.error("Error fetching dishes:", err);
        res.status(500).send("Error retrieving dishes");
    }
});

app.get("/veg",async(req,res)=>{
   
    try {
        const result = await db.query("SELECT * FROM products WHERE category='Veg' ORDER BY id ASC;");
        const dishes = result.rows;
        if(!req.user){
            return res.render("menu.ejs", { 
                dishes:dishes,
                user:null,
            });
        }
        else{
            return res.render("menu.ejs", { 
                dishes:dishes,
                user:req.user.username,
            });
            
        }
    } catch (err) {
        console.error("Error fetching dishes:", err);
        res.status(500).send("Error retrieving dishes");
    }
})
app.get("/nonveg",async(req,res)=>{
  
    try {
        const result = await db.query("SELECT * FROM products WHERE category='Non-Veg' ORDER BY id ASC;");
        const dishes = result.rows;
        if(!req.user){
            return res.render("menu.ejs", { 
                dishes:dishes,
                user:null,
            });
        }
        else{
            return res.render("menu.ejs", { 
                dishes:dishes,
                user:req.user.username,
            });
            
        }
    } catch (err) {
        console.error("Error fetching dishes:", err);
        res.status(500).send("Error retrieving dishes");
    }
})
app.get("/chicken",async(req,res)=>{
    
    try {
        const result = await db.query("select * from products where type='Chicken' ORDER BY id ASC;");
        const dishes = result.rows;
        if(!req.user){
            return res.render("menu.ejs", { 
                dishes:dishes,
                user:null,
            });
        }
        else{
            return res.render("menu.ejs", { 
                dishes:dishes,
                user:req.user.username,
            });
            
        }
    } catch (err) {
        console.error("Error fetching dishes:", err);
        res.status(500).send("Error retrieving dishes");
    }
})
app.get("/mutton",async(req,res)=>{
    
    try {
        const result = await db.query("select * from products where type='Mutton' ORDER BY id ASC;");
        const dishes = result.rows;
        if(!req.user){
            return res.render("menu.ejs", { 
                dishes:dishes,
                user:null,
            });
        }
        else{
            return res.render("menu.ejs", { 
                dishes:dishes,
                user:req.user.username,
            });
            
        }
    } catch (err) {
        console.error("Error fetching dishes:", err);
        res.status(500).send("Error retrieving dishes");
    }
})
app.get("/seafood",async(req,res)=>{
    
    try {
        const result = await db.query("select * from products where type='Seafood' ORDER BY id ASC;");
        const dishes = result.rows;
        if(!req.user){
            return res.render("menu.ejs", { 
                dishes:dishes,
                user:null,
            });
        }
        else{
            return res.render("menu.ejs", { 
                dishes:dishes,
                user:req.user.username,
            });
            
        }
    } catch (err) {
        console.error("Error fetching dishes:", err);
        res.status(500).send("Error retrieving dishes");
    }
})
app.get("/biryani",async(req,res)=>{
    
    try {
        const result = await db.query("select * from products where biryani=true ORDER BY id ASC;");
        const dishes = result.rows;
        if(!req.user){
            return res.render("menu.ejs", { 
                dishes:dishes,
                user:null,
            });
        }
        else{
            return res.render("menu.ejs", { 
                dishes:dishes,
                user:req.user.username,
            });
            
        }
    } catch (err) {
        console.error("Error fetching dishes:", err);
        res.status(500).send("Error retrieving dishes");
    }
})
app.get("/cart/add",(req,res)=>{
    res.redirect("/");
})
app.post("/cart/add",checkNotAuthenticated,async(req,res)=>{
    try {
        const { item_id, quantity } = req.body;
        const user_id = req.user.id; // Assuming `req.user` contains the logged-in user data

        // Check if the product exists
        const productCheck = await db.query("SELECT count FROM products WHERE id = $1", [item_id]);

        if (productCheck.rows.length === 0) {
            req.flash("error", "Product not found");
            return res.redirect("back");
        }

        const maxQuantity = productCheck.rows[0].count;
        if (quantity > maxQuantity) {
            req.flash("error", `Only ${maxQuantity} items available`);
            return res.redirect("back");
        }

        // Check if item is already in cart
        const cartCheck = await db.query("SELECT quantity FROM cart WHERE user_id = $1 AND product_id = $2", [user_id, item_id]);

        if (cartCheck.rows.length > 0) {
            // Update quantity if item is already in cart
            const newQuantity = Math.min(cartCheck.rows[0].quantity , quantity);
            await db.query("UPDATE cart SET quantity = $1,is_available=true WHERE user_id = $2 AND product_id = $3", [newQuantity, user_id, item_id]);
        } else {
            // Insert new item into cart
            await db.query("INSERT INTO cart (user_id, product_id, quantity) VALUES ($1, $2, $3)", [user_id, item_id, quantity]);
        }

        req.flash("success", "Item added to cart successfully");
        res.redirect("back");

    } catch (error) {
        console.error("Error adding item to cart:", error);
        res.status(500).json({ message: "Internal server error" });
    }
})
app.get("/cart", checkNotAuthenticated, async (req, res) => {
    try {
        const user_id = req.user.id;

        // Update cart item availability based on stock
        await db.query(`
            UPDATE cart
            SET is_available = FALSE
            FROM products
            WHERE cart.product_id = products.id 
            AND cart.quantity > products.count
        `);
        await db.query(`
            UPDATE cart
            SET is_available = true
            FROM products
            WHERE cart.product_id = products.id 
            AND cart.quantity <= products.count
        `);
        
        const cartItems = await db.query(`
            SELECT cart.id, products.name, cart.quantity, products.count AS max_count, 
                   products.image, products.price, 
                   (cart.quantity * products.price) AS amount,
                   cart.is_available
            FROM cart 
            JOIN products ON cart.product_id = products.id
            WHERE cart.user_id = $1
        `, [user_id]);

        // Separate available and unavailable items
        const availableItems = cartItems.rows.filter(item => item.quantity <= item.max_count);
        const unavailableItems = cartItems.rows.filter(item => item.quantity > item.max_count);

        // Calculate total amount
        const totalAmount = availableItems.reduce((sum, item) => sum + item.amount, 0);

        // Fetch flash messages (Ensure they are not empty)
        const successMessages = req.flash("success");
        const errorMessages = req.flash("error");
        console.log(successMessages);
        console.log(errorMessages);
        res.render("cart.ejs", { 
            availableItems, 
            unavailableItems,
            totalAmount,
            successMessage: successMessages.length > 0 ? successMessages.join(', ') : null,
            errorMessage: errorMessages.length > 0 ? errorMessages.join(', ') : null
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
    }
});


app.post('/cart/buy/:id', checkNotAuthenticated, async (req, res) => {
    const itemId = req.params.id;

    try {
        // Get the product ID and quantity from the cart
        const cartItem = await db.query("SELECT product_id, quantity FROM cart WHERE id = $1", [itemId]);
        
        if (cartItem.rows.length === 0) {
            req.flash('error', '❌ Item not found in cart.');
            return res.redirect('/cart');
        }

        const { product_id, quantity } = cartItem.rows[0];
        const product = await db.query("SELECT count AS max_count, name FROM products WHERE id = $1", [product_id]);
        const { max_count, name } = product.rows[0];

        if (quantity > max_count) {
            req.flash('error', `❌ ${name} only has ${max_count} items available.`);
            return res.redirect('/cart');
        }

        // Reduce the quantity in the products table
        await db.query("UPDATE products SET count = count - $1 WHERE id = $2", [quantity, product_id]);

        // Remove item from cart after purchase
        await db.query("DELETE FROM cart WHERE id = $1", [itemId]);

        req.flash('success', `🎉 Purchased: ${name}`);
        res.redirect('/cart');
    } catch (error) {
        console.error('Error buying item:', error);
        req.flash('error', '❌ Failed to purchase item.');
        res.redirect('/cart');
    }
});

/* 🗑 DELETE ITEM */
app.post('/cart/delete/:id', checkNotAuthenticated,async (req, res) => {
    const itemId = req.params.id;

    try {
        await db.query("DELETE FROM cart WHERE id = $1", [itemId]);
        console.log('🗑️ Item removed from cart.')
        req.flash('success', '🗑️ Item removed from cart.');
       
        res.redirect('/cart');
    } catch (error) {
        console.error('Error deleting item:', error);
        req.flash('error', '❌ Failed to remove item.');
        res.redirect('/cart');
    }
});
app.post('/cart/buy-all', checkNotAuthenticated, async (req, res) => {
    const user_id = req.user.id;
    try {
        const cartItems = await db.query(`
            SELECT c.product_id, c.quantity, p.count, p.name, c.is_available
            FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = $1
        `, [user_id]);

        if (cartItems.rows.length === 0) {
            req.flash('error', '❌ No items in cart to purchase.');
            return res.redirect('/cart');
        }

        let purchasedItems = [];
        let outOfStockItems = [];

        for (let item of cartItems.rows) {
            if (item.quantity <= item.count) {
                await db.query("UPDATE products SET count = count - $1 WHERE id = $2", [item.quantity, item.product_id]);
                await db.query("DELETE FROM cart WHERE product_id = $1 AND user_id = $2", [item.product_id, user_id]);
                purchasedItems.push(item.name);
            } else if (item.is_available) {
                outOfStockItems.push(`${item.name} (Available: ${item.count}, Requested: ${item.quantity})`);
            }
        }
        console.log(purchasedItems);
        console.log(outOfStockItems)
        // Store flash messages properly
        if (purchasedItems.length > 0) {
            req.flash('success', `🎊 Purchased: ${purchasedItems.join(', ')}`);
        }

        if (outOfStockItems.length > 0) {
            req.flash('error', `⛔ Unavailable: ${outOfStockItems.join(', ')}`);
        }

        res.redirect('/cart');
    } catch (error) {
        console.error('Error buying all items:', error);
        req.flash('error', '❌ Failed to purchase items.');
        res.redirect('/cart');
    }
});

app.post('/submit-review', checkNotAuthenticated, async (req, res) => {
    const { rating, feedback, product_id } = req.body;
    const userId = req.user.id; // Assuming user is logged in

    if (!product_id || !rating || !feedback) {
        req.flash("error", "⚠️ All fields are required.");
        return res.redirect("back");
    }

    try {
        // Check if user already submitted a review
        const check = await db.query("SELECT * FROM reviews WHERE user_id = $1 AND product_id = $2", 
            [userId, product_id]
        );

        // Get product details
        const product = await db.query("SELECT * FROM products WHERE id = $1", [product_id]);
        if (product.rows.length === 0) {
            req.flash("error", "❌ Product not found.");
            return res.redirect("back");
        }

        let totalRating = parseFloat(product.rows[0].feedback);
        let ratingCount = parseInt(product.rows[0].feedback_count);
        let newRating = parseFloat(rating);

        if (check.rows.length > 0) {
            // Update existing review
            const prevRating = check.rows[0].rating;
            totalRating = totalRating + newRating - prevRating; // Adjust total rating

            let updatedRating = (totalRating / ratingCount).toFixed(1); // Maintain decimal precision

            await db.query("UPDATE products SET feedback = $1, rating = $2 WHERE id = $3", 
                [totalRating, updatedRating, product_id]
            );

            await db.query("UPDATE reviews SET rating = $1, feedback = $2 WHERE user_id = $3 AND product_id = $4", 
                [newRating, feedback, userId, product_id]
            );

            req.flash("success", "✅ Review updated successfully!");
        } else {
            // Insert new review
            totalRating += newRating;
            ratingCount += 1;
            let updatedRating = (totalRating / ratingCount).toFixed(1);

            await db.query("INSERT INTO reviews (user_id, product_id, rating, feedback) VALUES ($1, $2, $3, $4)",
                [userId, product_id, newRating, feedback]
            );

            await db.query("UPDATE products SET feedback = $1, feedback_count = $2, rating = $3 WHERE id = $4", 
                [totalRating, ratingCount, updatedRating, product_id]
            );

            req.flash("success", "✅ Review submitted successfully!");
        }

        res.redirect("back");

    } catch (error) {
        console.error("❌ Error submitting review:", error);
        req.flash("error", "⚠️ Internal Server Error.");
        res.redirect("back");
    }
});
app.get("/view-reviews",(req,res)=>{
    res.redirect("back");
})
app.post("/view-reviews",async (req,res)=>{
    const productId=req.body.product_id;
    try {
        // Fetch product details
        const productQuery = await db.query(
            "SELECT id, name, image, rating, price FROM products WHERE id = $1",
            [productId]
        );

        if (productQuery.rows.length === 0) {
            req.flash("error", "Product not found.");
            return res.redirect("back");
        }

        const product = productQuery.rows[0];

        // Fetch reviews along with user names
        const reviewsQuery = await db.query(
            `SELECT u.username, r.rating, r.feedback 
            FROM reviews r 
            JOIN users u ON r.user_id = u.id 
            WHERE r.product_id = $1 
            ORDER BY r.id DESC`,
            [productId]
        );

        res.render("reviews.ejs", { product, reviews: reviewsQuery.rows });
    } catch (error) {
        console.error("Error fetching reviews:", error);
        req.flash("error", "Something went wrong.");
        res.redirect("/");
    }
})

app.get("/logout", (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        req.flash("success-message", "You have successfully logged out.");
        res.redirect("/");
    });
});

app.post("/logout", (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        req.flash("success-message", "You have successfully logged out.");
        res.redirect("/");
    });
});

function checkAuthenticated(req,res,next){
    if(req.isAuthenticated()){
        return res.redirect("/");
    }
    next();
}

function checkNotAuthenticated(req,res,next){
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect("/login");
    
}
passport.use(
    new Strategy({ usernameField: "username" }, async (username, password, done) => {
        try {
            const result = await db.query("SELECT * FROM users WHERE username=$1;", [username]);

            if (result.rows.length === 0) {
                return done(null, false, { message: "Invalid Username" }); // ✅ This should trigger failureFlash
            }

            const user = result.rows[0];

            if (!user.is_verified) {
                return done(null, false, { message: "Please verify your email before logging in." });
            }

            bcrypt.compare(password, user.password, (err, isValid) => {
                if (err) return done(err);
                return isValid ? done(null, user) : done(null, false, { message: "Password not matched" });
            });
        } catch (err) {
            return done(err);
        }
    })
);



passport.use("admin-local",
    new Strategy({ usernameField: "username" }, async (username, password, done) => {
        try {
            const result = await db.query("SELECT * FROM admin WHERE username=$1;", [username]);

            if (result.rows.length === 0) {
                console.log("❌ Invalid Admin Username");
                return done(null, false, { message: "Invalid Admin Username" });
            }

            const admin = result.rows[0];

            bcrypt.compare(password, admin.password, (err, isValid) => {
                if (err) return done(err);
                if (isValid) {
                    // console.log("✅ Admin Login Successful:", admin);
                    admin.role = "admin"; // Ensure admin has a role
                    return done(null, admin);
                } else {
                    console.log("❌ Incorrect Admin Password");
                    return done(null, false, { message: "Incorrect Password" });
                }
            });
        } catch (err) {
            console.error("❌ Admin Login Error:", err);
            return done(err);
        }
    })
);

// ✅ Serialize & Deserialize Admin
passport.serializeUser((user, done) => {
    
    
    // Check if the user exists in the 'admin' table to assign 'admin' role
    const role = "role" in user? "admin" : "user"; // is_admin should come from DB
    
    done(null, { id: user.username, role });
});

passport.deserializeUser(async (data, done) => {
    try {
        

        let result;
        if (data.role === "admin") {
            result = await db.query("SELECT * FROM admin WHERE username=$1;", [data.id]);
        } else {
            result = await db.query("SELECT * FROM users WHERE username=$1;", [data.id]);
        }

        if (result.rows.length > 0) {
            
            done(null, result.rows[0]);
        } else {
           
            done(null, false);
        }
    } catch (err) {
        console.error("Error in deserializing user:", err);
        done(err, null);
    }
});

// ✅ Admin Login Page (GET)
app.get("/admin/login", checkAdminAuthenticated, (req, res) => {
    const errorMessages = req.flash("error");
    res.render("adminLogin.ejs", { errors: errorMessages });
});

// ✅ Admin Login Handling (POST)
app.post("/admin/login", passport.authenticate("admin-local", {
    successRedirect: "/admin/dashboard",
    failureRedirect: "/admin/login",
    failureFlash: true
}));

// ✅ Admin Dashboard (Protected Route)
app.get("/admin/dashboard", checkNotAdminAuthenticated, (req, res) => {
    res.render("adminDashboard.ejs", { admin: req.user });
});

// ✅ Admin Logout
app.get("/admin/logout", (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        req.flash("success-message", "Admin logged out successfully.");
        res.redirect("/");
    });
});

// ✅ Middleware to Prevent Access if Already Logged In
function checkAdminAuthenticated(req, res, next) {
    if (req.isAuthenticated() && req.user.role === "admin") {
        return res.redirect("/admin/dashboard");
    }
    next();
}

// ✅ Middleware to Protect Admin Routes
function checkNotAdminAuthenticated(req, res, next) {
    if (!req.isAuthenticated() || req.user.role !== "admin") {
        return res.redirect("/admin/login");
    }
    next();
}

// ✅ Start Server

app.get("/admin/menu", checkNotAdminAuthenticated, async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM products ORDER BY id ASC;");
        res.render("adminMenu.ejs", { products: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server Error");
    }
});
app.get("/upload",checkNotAdminAuthenticated, (req,res)=>{
    res.render("upload.ejs",{
        name:"",
        category:"",
        type:"",
        biryani:false,
        image:null,
        count:0,
        price:0,
        id:null,
    })

})

app.post("/upload", checkNotAdminAuthenticated, upload.single("image"), async (req, res) => {
    let { name, category, type, price, count, biryani, id } = req.body;
    const image = req.file ? req.file.filename : null; // Store filename if uploaded

    try {
        // 🔹 Ensure required fields are not missing
        if (!name || !category || !price || !count) {
            req.flash("error", "Missing required fields. Please fill all details.");
            return res.redirect("/upload");
        }

        // 🔹 Convert data to correct types (ensure numbers are not empty strings)
        price = price ? parseFloat(price) : null;
        count = count ? parseInt(count, 10) : null;
        id = id ? parseInt(id, 10) : null; // Convert id only if provided

        // 🔹 Check if price and count are valid numbers
        if (isNaN(price) || isNaN(count)) {
            req.flash("error", "Invalid price or count. Please enter valid numbers.");
            return res.redirect("/upload");
        }

        // 🔹 Check if the dish exists (only if updating)
        if (id) {
            const product = await db.query("SELECT * FROM products WHERE id = $1", [id]);
            if (product.rows.length > 0) {
                // ✅ Update existing product
                if (image) {
                    await db.query(
                        `UPDATE products SET name=$1, category=$2, type=$3, price=$4, count=$5, biryani=$6, image=$7 WHERE id=$8 RETURNING *;`,
                        [name, category, type || null, price, count, biryani === "yes", image, id]
                    );
                } else {
                    await db.query(
                        `UPDATE products SET name=$1, category=$2, type=$3, price=$4, count=$5, biryani=$6 WHERE id=$7 RETURNING *;`,
                        [name, category, type || null, price, count, biryani === "yes", id]
                    );
                }
                console.log("Dish updated:", name);
                req.flash("success", "Dish updated successfully!");
            } else {
                req.flash("error", "Dish not found. Please try again.");
                return res.redirect("/upload");
            }
        } else {
            // ✅ Insert new product
            const result = await db.query(
                `INSERT INTO products (name, category, type, price, count, biryani, image) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;`,
                [name, category, type || null, price, count, biryani === "yes", image]
            );
            console.log("Dish added:", result.rows[0]);
            req.flash("success", "Dish added successfully!");
        }

        return res.redirect("/admin/menu");
    } catch (err) {
        console.error("Error adding/updating dish:", err);
        req.flash("error", "Failed to process dish. Please try again.");
        return res.redirect("/upload");
    }
});




// Add a new product

// Update a product
app.post("/admin/menu/update", checkNotAdminAuthenticated, async (req, res) => {
    const id=req.body.id;
    try{
        const product=await db.query("select * from products where id=$1",[id]);
        
        const pr=product.rows[0];
        console.log(pr)
        res.render("upload.ejs",{
            name:pr.name,
            category:pr.category,
            type:pr.type,
            biryani:pr.biryani,
            image:pr.image,
            count:pr.count,
            price:pr.price,
            id:pr.id
        })
    }catch(err){
        console.log(err);
        res.redirect("/admin/menu");
    }

});

// Delete a product
app.post("/admin/menu/delete", checkNotAdminAuthenticated, async (req, res) => {
    const id=req.body.id;
    try {
        await db.query("DELETE FROM products WHERE id=$1;", [id]);
        res.redirect("/admin/menu");
    } catch (err) {
        console.error(err);
        res.status(500).send("Error deleting product");
    }
});

app.get("/admin/staff",checkNotAdminAuthenticated,async(req,res)=>{
    try {
        const result = await db.query("SELECT * FROM staff ORDER BY id ASC;");
        res.render("staffData.ejs", { staff: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server Error");
    }
})

app.post("/admin/staff/add",checkNotAdminAuthenticated,async(req,res)=>{
    res.redirect("/staffupload");
})
app.get("/staffupload",checkNotAdminAuthenticated,async(req,res)=>{
    res.render("staffUpload.ejs",{
        name:null,
        gender:null,
        experience:null,
        id:null,
        phone:null,
        salary:null,
        image:null,
        role:null
    })
})
app.post("/staffupload", upload.single("image"), async (req, res) => {
    let { name, gender, experience, phone, salary, role, id } = req.body;
    const image = req.file ? req.file.filename : null; // Store filename if uploaded

    // Convert empty strings to null or default values
    experience = experience.trim() === "" ? null : parseInt(experience, 10);
    phone = phone.trim() === "" ? null : phone; // Keep phone as string (if applicable)
    salary = salary.trim() === "" ? null : parseFloat(salary);
    id = id.trim() === "" ? null : parseInt(id, 10);

    console.log("Received Data:", { name, gender, experience, phone, salary, role, id });

    try {
        const staff = await db.query("SELECT * FROM staff WHERE id = $1", [id]);

        if (staff.rows.length === 0) {
            // Insert new staff
            const result = await db.query(
                "INSERT INTO staff (name, gender, experience, phone, salary, role, image) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;",
                [name, gender, experience, phone, salary, role, image]
            );
            console.log("Staff added:", result.rows[0]);
            req.flash("success", "Staff added successfully!");
        } else {
            // Update existing staff
            if (image) {
                await db.query(
                    "UPDATE staff SET name=$1, gender=$2, experience=$3, phone=$4, salary=$5, role=$6, image=$7 WHERE id=$8 RETURNING *;",
                    [name, gender, experience, phone, salary, role, image, id]
                );
            } else {
                await db.query(
                    "UPDATE staff SET name=$1, gender=$2, experience=$3, phone=$4, salary=$5, role=$6 WHERE id=$7 RETURNING *;", 
                    [name, gender, experience, phone, salary, role, id]
                );
            }
            console.log("Staff updated:", name);
            req.flash("success", "Staff updated successfully!");
        }

        return res.redirect("/admin/staff");
    } catch (err) {
        console.error("Error adding/updating staff:", err);
        req.flash("error", "Failed to process staff data. Please try again.");
        return res.redirect("/staffupload");
    }
});
app.get("/admin/staff/update",checkNotAdminAuthenticated,(req,res)=>{
    res.redirect("/admin/staff");
})
app.post("/admin/staff/update",checkNotAdminAuthenticated,async(req,res)=>{
    const id=req.body.id;
    try{
        const result=await db.query("select * from staff where id=$1",[id]);
        const staff=result.rows[0];
        res.render("staffUpload.ejs",{
            name:staff.name,
            gender:staff.gender,
            experience:staff.experience,
            id:staff.id,
            phone:staff.phone,
            salary:staff.salary,
            image:staff.image,
            role:staff.role
        })
    }
    catch(err){
        console.log(err);
        res.redirect("/admin/staff");
    }
})
app.get("/admin/staff/delete",checkNotAdminAuthenticated,(req,res)=>{
    res.redirect("/admin/staff");
})
app.post("/admin/staff/delete",checkNotAdminAuthenticated,async(req,res)=>{
    const id=req.body.id;
    try{
        const result=await db.query("DELETE FROM staff WHERE id = $1;",[id]);
        return res.redirect("/admin/staff");
    }
    catch(err){
        console.log(err);
        res.redirect("/admin/staff");
    }
})
app.get("/contact",(req,res)=>{
    if(!req.user){
        return res.render("contact.ejs",{
            use:null,
        });
    }
    else{
        console.log(req.user);
        return res.render("contact.ejs",{
            use:req.user.username,
        });
    }
})
app.listen(port,()=>{
    console.log(`server running on ${port}`);
});