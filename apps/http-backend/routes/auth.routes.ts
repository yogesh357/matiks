import { loginSchema, registerSchema, zodErrorMessage } from "@repo/common/common";
import { Router } from "express";
import { prisma } from "@repo/db/client";
import { hash, compare } from "bcryptjs";
// @ts-ignore
import jwt from "jsonwebtoken";
import { authMiddleware } from "../middleware/auth.middleware";

const JWT_SECRET = process.env.JWT_SECRET || "jwt_secret";

const router = Router();

router.post("/register", async (req, res) => {
    try {
        const parsedData = registerSchema.safeParse(req.body);
        if (!parsedData.success) {
            return res.status(400).json({
                message: zodErrorMessage({ error: parsedData.error })
            });
        }

        const { email, password } = parsedData.data;

        const existingUser = await prisma.user.findUnique({
            where: { email }
        });

        if (existingUser) {
            return res.status(409).json({
                message: "User with this email already exists"
            });
        }

        let username = req.body.username || email.split("@")[0];
        const existingUsername = await prisma.user.findUnique({
            where: { username }
        });

        if (existingUsername) {
            username = `${username}_${Math.random().toString(36).substring(2, 6)}`;
        }

        const hashedPassword = await hash(password, 10);

        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,
                username,
            },
            select: {
                id: true,
                email: true,
                username: true,
            }
        });

        const token = jwt.sign({ id: user.id }, JWT_SECRET);

        return res.status(201).json({
            message: "User registered successfully",
            token,
            user,
        });
    } catch (error) {
        console.error("Register error:", error);
        return res.status(500).json({
            message: "Internal server error"
        });
    }
});

router.post("/login", async (req, res) => {
    try {
        const parsedData = loginSchema.safeParse(req.body);
        if (!parsedData.success) {
            return res.status(400).json({
                message: zodErrorMessage({ error: parsedData.error })
            });
        }

        const { email, password } = parsedData.data;

        const user = await prisma.user.findUnique({
            where: { email }
        });

        if (!user) {
            return res.status(403).json({
                message: "Invalid email or password"
            });
        }

        const isPasswordValid = await compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(403).json({
                message: "Invalid email or password"
            });
        }

        const token = jwt.sign({ id: user.id }, JWT_SECRET);

        return res.status(200).json({
            message: "Logged in successfully",
            token,
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
            }
        });
    } catch (error) {
        console.error("Login error:", error);
        return res.status(500).json({
            message: "Internal server error"
        });
    }
});

router.get("/me", authMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        if (!userId) {
            return res.status(401).json({
                message: "Unauthorized"
            });
        }

        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: {
                id: true,
                email: true,
                username: true,
                rating: true,
                gameMember: {
                    include: {
                        game: true
                    }
                }
            },
        });

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        return res.status(200).json({
            user
        });
    } catch (error) {
        return res.status(500).json({
            message: "Internal server error"
        });
    }
});

export default router;