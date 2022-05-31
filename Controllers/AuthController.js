const User = require("../Models/UserModel");
const Token = require("../Models/TokenModel");

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } = process.env;

const AuthController = {
    signup: async (req, res) => {
        try {
            //check if username is already taken:
            let user = await User.findOne({ username: req.body.username });
            if (user) {
                return res.status(400).json({
                    success: false,
                    error: 'Username is taken'
                });
            } else {

                //save user to our db
                user = await new User(req.body).save();

                return res.status(201).json({
                    success: true,
                    data: user
                });
            }
        } catch (error) {
            // console.error(error);
            return res.status(500).json({
                success: false,
                error: error
            });
        }
    },

    login: async (req, res) => {
        try {

            //check if user exists in database:
            let user = await User.findOne({ username: req.body.username });
            //send error if no user found:
            if (!user) {
                return res.status(400).json({
                    success: false,
                    error: 'User not found'
                });
            } else {
                //check if password is valid:
                let valid = await bcrypt.compare(req.body.password, user.password);
                if (valid) {

                    //generate a pair of tokens if valid and send
                    let accessToken = await user.createAccessToken();
                    let refreshToken = await user.createRefreshToken();

                    // update the latest refresh token to user table
                    await User.updateOne({ _id: user.id }, { $set: { refreshToken: refreshToken } });

                    return res.status(200).json({
                        success: true,
                        accessToken: accessToken,
                        refreshToken: refreshToken
                    });
                } else {
                    //send error if password is invalid
                    return res.status(401).json({
                        success: false,
                        error: 'Invalid Password!'
                    });
                }
            }
        } catch (error) {
            console.error(error);
            return res.status(500).json({
                success: false,
                error: error
            });
        }
    },

    generateRefreshToken: async (req, res) => {
        try {
            //get refreshToken
            const refreshToken = req.body.refreshToken;

            //send error if no refreshToken is sent
            if (!refreshToken) {
                return res.status(403).json({ error: "Access denied,token missing!" });
            } else {

                console.log('refreshToken', refreshToken)

                //query for the token to check if it is valid:
                const tokenDoc = await User.findOne({ refreshToken: refreshToken });


                //send error if no token found:
                if (!tokenDoc) {
                    return res.status(401).json({ error: "Token expired!" });
                } else {

                    //extract payload from refresh token and generate a new access token and send it
                    const refreshTokenData = jwt.verify(tokenDoc.refreshToken, REFRESH_TOKEN_SECRET);

                    console.log('fffffffffffffffff', refreshTokenData);


                    const accessToken = jwt.sign({ user: { id: refreshTokenData.user._id, username: refreshTokenData.user.username } }, ACCESS_TOKEN_SECRET, {
                        expiresIn: "7d",
                    });


                    // await User.updateOne({ _id: user.id }, { $set: { refreshToken: refreshToken } });


                    return res.status(200).json({ accessToken });
                }
            }
        } catch (error) {
            console.error(error);
            return res.status(500).json({ error: "Internal Server Error!" });
        }
    },

    logout: async (req, res) => {
        try {
            //delete the refresh token saved in database:
            //get refreshToken
            const refreshToken = req.body.refreshToken;

            //send error if no refreshToken is sent

            if (!refreshToken) {
                return res.status(403).json({ error: "Access denied,token missing!" });
            } else {

                let tokenData = await Token.findOneAndDelete({ token: refreshToken });

                if (!tokenData) {

                    return res.status(403).json({ error: "Access denied,Token is expired!" });

                }

                return res.status(200).json({ success: "User logged out!" });
            }
        } catch (error) {
            console.error(error);
            return res.status(500).json({ error: "Internal Server Error!" });
        }
    },
}
module.exports = AuthController
