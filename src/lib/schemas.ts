import { z } from "zod";

const COMMON = new Set([
  "password", "password1", "password12", "password123", "passw0rd123", "qwerty123", "qwertyuiop", "1234567890", "12345678910",
  "iloveyou123", "welcome123", "admin12345", "letmein123", "abc1234567", "changeme123", "0123456789", "1q2w3e4r5t", "qazwsx123",
]);

export const email = z.string().trim().toLowerCase().max(254).email("Enter a valid email address.");

export const username = z
  .string()
  .trim()
  .min(3, "Username must be at least 3 characters.")
  .max(30, "Username can be at most 30 characters.")
  .regex(/^[a-zA-Z0-9_]+$/, "Use only letters, numbers and underscores.");

/** Digits with an optional leading +, 7 to 15 digits (E.164). Spaces, dashes and brackets are ignored. */
export const contact = z
  .string()
  .trim()
  .max(24)
  .transform((v) => v.replace(/[\s()-]/g, ""))
  .refine((v) => /^\+?[0-9]{7,15}$/.test(v), "Enter a valid phone number, for example +919876543210.");

export const password = z
  .string()
  .min(10, "Password must be at least 10 characters.")
  .max(128, "Password can be at most 128 characters.")
  .refine((v) => /[A-Za-z]/.test(v) && /[0-9]/.test(v), "Use at least one letter and one number.")
  .refine((v) => !COMMON.has(v.toLowerCase()), "That password is too common. Choose another.");

export const signupBody = z
  .object({ username, email, contact, password })
  .refine((v) => v.password.toLowerCase() !== v.username.toLowerCase() && !v.password.toLowerCase().includes(v.email.split("@")[0]!.toLowerCase()), {
    message: "Password must not contain your username or email name.",
    path: ["password"],
  });

export const loginBody = z.object({
  identifier: z.string().trim().min(3).max(254), // email or username
  password: z.string().min(1).max(128),
});

export const googleBody = z.object({ credential: z.string().min(20).max(4096) });
export const forgotBody = z.object({ email });
export const resetBody = z.object({ token: z.string().min(20).max(200), password });
export const verifyBody = z.object({ token: z.string().min(20).max(200) });

export type SignupBody = z.infer<typeof signupBody>;
