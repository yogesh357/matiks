import z, { ZodError } from "zod"


export const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6),

})

export const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
})

export const zodErrorMessage = ({ error }: { error: ZodError }) => {
    return error.issues
        .map((er) => `path:${er.input}, message:${er.message}`)
        .join(",")
}

export type RegisterInput = z.infer<typeof registerSchema>
export type LoginInput = z.infer<typeof loginSchema>
