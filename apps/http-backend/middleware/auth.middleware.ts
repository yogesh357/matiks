import type { Request, Response, NextFunction } from "express";
import { prisma } from "@repo/db/client";
// @ts-ignore
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "jwt_secret";


export const authMiddleware = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({
                message: "Unauthorized: No token provided",
            });
        }

        const token = authHeader.startsWith("Bearer ")
            ? authHeader.split(" ")[1]
            : authHeader;

        if (!token) {
            return res.status(401).json({
                message: "Unauthorized: Invalid token format",
            });
        }

        const decoded = jwt.verify(token, JWT_SECRET) as {
            id?: string;
            userId?: string;
        };

        const userId = decoded.id || decoded.userId;

        if (!userId) {
            return res.status(401).json({
                message: "Unauthorized: Invalid token payload",
            });
        }

        const user = await prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            return res.status(401).json({
                message: "Unauthorized: User does not exist",
            });
        }

        req.userId = user.id;
        next();
    } catch (error) {
        return res.status(401).json({
            message: "Unauthorized: Invalid or expired token",
        });
    }
};

export default authMiddleware;